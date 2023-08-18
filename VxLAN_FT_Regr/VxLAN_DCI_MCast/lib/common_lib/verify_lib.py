
import sys, copy, re, random, time, pexpect, datetime, time
from common_lib import parserutils_lib
from common_lib import utils
from common_lib.utils import *

class verifyShowProcessLogs():
  "  verifyShowProcessLogs - Method to verify if any process logs are seen\
  \
  mandatory args\
  \
  hdl - switch handle object from icon\
  log - harness/python logging object\
  "
  def __init__(self, hdl, log):
     
      self.result='pass'
      show_process_log=hdl.iexec('show process log')
      ## 
      pattern = '\s+{0}\s+({1})\s+{2}\s+{2}\s+{2}\s+{3}\s+{3}\s+{1}\s+{4}'.\
          format(rex.SYSMGR_SERVICE_NAME,rex.NUM,rex.ALPHAUPPER,rex.ALPHA,rex.CLOCK_TIME)
      process_log_list = re.findall(pattern,show_process_log)
      if not process_log_list:
          log.info ('No Process logs found on {0}'.format(hdl.switchName))
      else:
          testResult ('fail','Process logs seen on {0}'.format(hdl.switchName),log)
          self.result = 'fail'
      
      for pid in process_log_list:
          cmd='show process log pid {0}'.format(pid)
          show_plog=hdl.iexec(cmd)
          log.error(show_plog)
          

class verifyConsistencyChecker():
  "  verifyConsistenchChecker - Method to verify consistency checer\
  \
  mandatory args\
  \
  hdl - switch handle object from icon\
  log - harness/python logging object\
  \
  Optional args: \
  \
  cc_list - po_mem,vlan_mem,link_state,stp,l2,l3,ipv4,ipv6,racl\
  log - harness/python logging object\
  \
  Usages:                                   \
      verifyConsistencyChecker(hdl, log)      \
      verifyConsistencyChecker(hdl, log, '-cc_list po_mem,stp,vlan_mem,link_state,l3,l2,racl,ipv4,ipv6)      \
      verifyConsistencyChecker(hdl, log, '-cc_list link_state,l3,l2,racl -modules 2,3)      \
      verifyConsistencyChecker(hdl, log, '-cc_list stp,vlan_mem -vlans 2,3)      \
      verifyConsistencyChecker(hdl, log, '-cc_list ipv4,ipv6 )      \
  "

  def __init__(self, hdl, log, *args):
      arggrammar = {}
      arggrammar['cc_list']='-type str -default all -subset ["po_mem","ipv4","ipv6","stp","vlan_mem","link_state","l3","l2","racl","all","ipv4_msdc","ipv6_msdc"]'
      arggrammar['modules']='-type str -default all'
      arggrammar['vlans']='-type str -default all'

      parse_output = parserutils_lib.argsToCommandOptions(args,arggrammar,log)
      cc_list = parse_output.cc_list
      mod_list = parse_output.modules
      vlan_list = parse_output.vlans

      if cc_list:
         cc_params = cc_list.split(',')

      if mod_list == 'all':
         dev_type = getDeviceType(hdl)
         # For Tor, only check module 1
         if 'C93' in dev_type:
            mod_params = ['1']
         else:
            mod_params = getModuleSlotList(hdl, log, type='LC')
      else:
         mod_params = mod_list.split(',')

      if vlan_list == 'all':
         vlan_params = getActiveVlanList(hdl, log)
      else:
         vlan_params = utils.strtoexpandedlist(vlan_list)

      self.result= 'pass' 
  
      cmd_dict = {'po_mem': 'show consistency-checker membership port-channels',
                  'ipv4': 'show consistency-checker forwarding ipv4 vrf all',
                  'ipv6': 'show consistency-checker forwarding ipv6 vrf all',
                  'stp':  'show consistency-checker stp-state vlan ',
                  'vlan_mem': 'show consistency-checker membership vlan ',
                  'link_state': 'show consistency-checker link-state module ',
                  'l3': 'show consistency-checker l3-interface module ',
                  'l2': 'show consistency-checker l2 module ',
                  'racl': 'show consistency-checker racl module ',
                  # Added as part of MSDC testcase
                  'ipv4_msdc': 'show forwarding ipv4 inconsistency module 1',
                  'ipv6_msdc': 'show forwarding ipv6 inconsistency module 1',

                 }
 
      result = 0
      for key, cmd in cmd_dict.items():
          if key in cc_params or 'all' in cc_params:
             if key == 'ipv4' or key == 'ipv6':
                op = hdl.iexec('test consistency-checker forwarding {0} vrf all'.format(key))
                if not re.search('Consistency check started.',op):
                   testResult('fail','Consistency checker not started for {0}'.format(key),log)
                   continue
                time.sleep(5)
                result += checkCCResult(hdl, cmd, log)

             elif key == 'ipv4_msdc' or key == 'ipv6_msdc':
                key1 = re.findall('(\S+)_msdc',key)[0]
                op = hdl.iexec('test forwarding {0} inconsistency module 1'.format(key1))
                if not re.search('Consistency check started.',op):
                   testResult('fail','Consistency checker not started for {0}'.format(key1),log)
                   continue
                time.sleep(5)
                result += checkCCResult(hdl, cmd, log)
                #hdl.iexec('test forwarding {0} inconsistency module 1 stop'.format(key1))

             elif key == 'stp' or key == 'vlan_mem':
                for vlan in vlan_params:
                   cmd_vlan = cmd + vlan                
                   result += checkCCResult(hdl, cmd_vlan, log)
   
             elif key == 'po_mem':
                output = hdl.iexec(cmd)
                result += checkCCResult(hdl, cmd, log)
    
             else:
                for mod in mod_params:
                   cmd_mod = cmd + mod               
                   result += checkCCResult(hdl, cmd_mod, log)
  
      if result: 
          testResult ('fail','Consistency checker failed at {0}'.format(hdl.switchName),log)
          self.result = 'fail'
      else:
          log.info ('Consistency checker passed at {0}'.format(hdl.switchName))


class verifyShowCores():
  "  verifyShowCores - Method to verify if any core files are seen\
  \
  mandatory args\
  \
  hdl - switch handle object from icon\
  log - harness/python logging object\
  "
  def __init__(self, hdl, log,*args):
     
      arggrammar={}

      arggrammar['clear_core']='-type bool -default True'
      arggrammar['user_name']='-type str -default snoopy'
      arggrammar['password']='-type str -default nbv123'
      arggrammar['destDir']='-type str -default /tmp'
      arggrammar['destIp']='-type str -format {0} -default 172.23.40.26'.format(rex.IPv4_ADDR)
      parse_output = parserutils_lib.argsToCommandOptions(args,arggrammar,log)
      clear_core = parse_output.clear_core
      destIp = parse_output.destIp
      destDir = parse_output.destDir
      user_name = parse_output.user_name
      password = parse_output.password
      self.result='pass'
      self.service_halt = False
      hdl.iexec('show logging logfile | grep -i crash')
      show_cores=hdl.iexec('show cores')
      if re.search('VDC',show_cores):
          pattern = '{0}\s+({0})\s+{0}\s+({1})\s+({0})\s+{2}\s+{3}'.\
          format(rex.NUM,rex.SYSMGR_SERVICE_NAME,rex.DATE,rex.CLOCK_TIME)
      else:
          pattern = '({0})\s+{0}\s+({1})\s+({0})\s+{2}\s+{3}'.\
          format(rex.NUM,rex.SYSMGR_SERVICE_NAME,rex.DATE,rex.CLOCK_TIME)
      core_list = re.findall(pattern,show_cores)
      if not core_list:
          log.info ('No Cores found on {0}'.format(hdl.switchName))
          core_copy_result = False
      else:
          testResult ('fail','Core file seen on {0}'.format(hdl.switchName),log)
          core_copy_result = True
          self.result = 'fail'
      sup_slots = utils.getSupSlots(hdl,log)
      for core_info in core_list:
          module=core_info[0]
          if module in sup_slots:
              if not self.service_halt:
                  # Check to see if service is still running
                  if (utils.getServicePid(hdl,log,core_info[1]) == 0):
                      log.debug ('Service {0} not running anymore'.format(core_info[1]))
                      self.service_halt = True
          else:
              # LC services are not restartable
              self.service_halt = True
          log.debug ('Copy core file for {0},module:{1},pid:{2}'.format(hdl.switchName,core_info[0],core_info[2]))
          if not (hdl.icopy('core:','scp://{0}/{1}'.format(destIp,destDir),'-module {0} -pid {1} -user_name {2} -password {3}'.\
                                format(core_info[0],core_info[2],user_name,password))):
              testResult('fail','Core copy not successful',log)
              core_copy_result = False
              break

      if (clear_core) and (core_copy_result): 
          hdl.hdl.sendline ('clear cores')
          i = hdl.hdl.expect(['assword:','# $'])
          if (i == 0):
              # Workaround for eor
              hdl.isendline ('insieme')
              #time.sleep(3)
              hdl.iexpect ('# $')
          else:
              log.debug ('No workaround needed')
              
class verifyPing():
  "  verifyPing - Method to verify ping to a list of destinations\
  \
  Mandatory Args\
  \
  hdl - icon switch object\
  log - harness/python logger object\
  dest_list - Comma separated list of IP addresses or host names\
  \
  Optional Args\
  \
  -source - Source IP to be used for ping\
  -packet_size - packet size to be used, default=64 bytes\
  -interval - time interval in sec between ping packets, default=0\
  -timeout - time value in secs for ping timeout, default=2 secs\
  -vrf - VRF name, default='default' vrf\
  -count - Number of ping packets to be used for verification, default=5\
  -negative - set to 1 if ping failure is expected with 100% loss\
  \
  Usage\
  \
  verifyPing( hdl, log, dest_list )\
  verifyPing( hdl, log, dest_list, '-source <SIP> -packet_size 64 -interval 1 -vrf management -count 5')"
  def __init__(self, hdl, log, dest_list, *args ):
     self.result='pass'

     arggrammar={}
     arggrammar['source']='-type str'
     arggrammar['packet_size']='-type int -default 64'
     arggrammar['interval']='-type int -default 0'
     arggrammar['timeout']='-type int -default 2'
     arggrammar['vrf']='-type str -default default'
     arggrammar['count']='-type int -default 5'
     arggrammar['df_bit']='-type bool -default False'
     arggrammar['negative']='-type bool -default False'
     ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
     destination_list=dest_list.split(',')

     if ns.df_bit:
         df_bit='df-bit'
     else:
         df_bit=''

     for destination in destination_list: 
         if ns.source:
             cmd='ping {0} source {1} packet-size {2} interval {3} timeout {4} vrf {5} count {6} {7}'.format(    \
                 destination, ns.source, ns.packet_size, ns.interval, ns.timeout, ns.vrf, ns.count, df_bit )
         else: 
             cmd='ping {0} packet-size {1} interval {2} timeout {3} vrf {4} count {5} {6}'.format(               \
                 destination, ns.packet_size, ns.interval, ns.timeout, ns.vrf, ns.count, df_bit )

         log.info('Verifying ping to destination {0} on {1}'.format(destination, hdl.switchName))
         ping_out=hdl.iexec(cmd)
         if not ns.negative:
             log.info('Positive case')
             if not re.search( ' 0.00% packet loss', ping_out, re.I ):
                 ## Adding wait as patch ## TODO # Add verify loop
#                 time.sleep(5)
                 ping_out_new=hdl.iexec(cmd)
                 if not re.search( ' 0.00% packet loss', ping_out_new, re.I ):
                     patstr='packet loss'
                     pattern='[ \t]+([0-9.%]+)[ \t]+{0}'.format(patstr)
                     pkt_loss=re.findall(pattern,ping_out_new, re.I)
                     testResult( 'fail', 'Ping to destination {0} on {1} failed, Expected 0.00% packet loss but received {2} packet loss'.\
                     format( destination, hdl.switchName, utils.listtostr(pkt_loss)), log )
                 else:
                     log.info('PASSED:Ping to destination {0} succeeded on {1}'.format(destination, hdl.switchName))
             else:
                 log.info('PASSED:Ping to destination {0} succeeded on {1}'.format(destination, hdl.switchName))
         else:
             log.info('Negative case')
             if not re.search( ' 100.00% packet loss', ping_out, re.I ):
                 patstr='packet loss'
                 pattern='[ \t]+([0-9.%]+)[ \t]+{0}'.format(patstr)
                 pkt_loss=re.findall(pattern,ping_out, re.I)
                 testResult( 'fail', 'Ping to destination {0} on {1} DID NOT fail, Expected 100.00% packet loss but received {2} packet loss'.\
                 format( destination, hdl.switchName, utils.listtostr(pkt_loss)), log )
             else:
                 log.info('PASSED: Ping to destination {0} failed on {1}'.format(destination, hdl.switchName))




class verifyPing6():
  "  verifyPing6 - Method to verify ping to a list of Ipv6 destinations\
  \
  Mandatory Args\
  \
  hdl - icon switch object\
  log - harness/python logger object\
  dest_list - Comma separated list of IP addresses or host names\
  \
  Optional Args\
  \
  -source - Source IPv6 address to be used for ping\
  -packet_size - packet size to be used, default=64 bytes\
  -interval - time interval in sec between ping packets, default=0\
  -timeout - time value in secs for ping timeout, default=2 secs\
  -vrf - VRF name, default='default' vrf\
  -count - Number of ping packets to be used for verification, default=5\
  -negative - when set, result will be pass for ping failures\
  \
  Usage\
  \
  verifyPing6( hdl, log, dest_list )\
  verifyPing6( hdl, log, dest_list, '-source <SIP_IPv6> -packet_size 64 -interval 1 -vrf management -count 5')"
  def __init__(self, hdl, log, dest_list, *args ):
     self.result='pass'

     arggrammar={}
     arggrammar['source']='-type str'
     arggrammar['packet_size']='-type int -default 64'
     arggrammar['interval']='-type int -default 0'
     arggrammar['timeout']='-type int -default 2'
     arggrammar['vrf']='-type str -default default'
     arggrammar['count']='-type int -default 5'
     arggrammar['interface']='-type str'
     arggrammar['negative']='-type bool -default False'
     ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
     destination_list=dest_list.split(',')

     for destination in destination_list:
         if ns.source:
             cmd='ping6 {0} source {1} packet-size {2} interval {3} timeout {4} vrf {5} count {6}'.format(         \
                 destination, ns.source, ns.packet_size, ns.interval, ns.timeout, ns.vrf, ns.count )
         else: 
             cmd='ping6 {0} packet-size {1} interval {2} timeout {3} vrf {4} count {5}'.format(                    \
                 destination, ns.packet_size, ns.interval, ns.timeout, ns.vrf, ns.count )

         log.info('Verifying ping6 to destination {0}'.format(destination))
         # If it is an IPv6 link local address ..
         if re.search( '^fe80', destination, re.I ):
             # if out going interface not given
             if not ns.interface:
                 testResult( 'fail', 'Outgoing Interface option is needed to ping6 link local address {0}, Please  \
                    provide the interface option'.format(destination), log )
             else:
                 hdl.isendline(cmd)
                 hdl.iexpect('Interface: $')
                 hdl.isendline(ns.interface)
                 ping_out=hdl.iexpect('# $')
                 if not ns.negative:
                     if not re.search( ' 0.00% packet loss', ping_out, re.I ):
                         hdl.isendline(cmd)
                         hdl.iexpect('Interface: $')
                         hdl.isendline(ns.interface)
                         ping_out_new=hdl.iexpect('# $')
                         if not re.search( ' 0.00% packet loss', ping_out_new, re.I ):
                             testResult( 'fail', 'Ping6 to destination {0} failed, Expected 0.00% packet loss but       \
                             {1}'.format( destination, ping_out_new ), log )
                         else:
                             log.info('PASSED:Ping6 to destination {0} succeeded'.format(destination))
                     else:
                         log.info('PASSED:Ping6 to destination {0} succeeded'.format(destination))
                 else:
                     log.info('Negative case')
                     if not re.search( ' 100.00% packet loss', ping_out, re.I ):
                         patstr='packet loss'
                         pattern='[ \t]+([0-9.%]+)[ \t]+{0}'.format(patstr)
                         pkt_loss=re.findall(pattern,ping_out, re.I)
                         testResult( 'fail', 'Ping6 to destination {0} on {1} DID NOT fail, Expected 100.00% packet loss but received {2} packet loss'.\
                         format( destination, hdl.switchName, utils.listtostr(pkt_loss)), log )
                     else:
                         log.info('PASSED:Ping6 to destination {0} failed on {1}'.format(destination, hdl.switchName))
                     
         # If not a link local address
         else:
             ping_out=hdl.iexec(cmd)
             if not ns.negative:
                 if not re.search( ' 0.00% packet loss', ping_out, re.I ):
                     ping_out_new=hdl.iexec(cmd)
                     if not re.search( ' 0.00% packet loss', ping_out_new, re.I ):
                         testResult( 'fail', 'Ping6 to destination {0} failed, Expected 0.00% packet loss but received   \
                         {1}'.format( destination, ping_out_new ), log )
                     else:
                         log.info('PASSED:Ping6 to destination {0} succeeded'.format(destination))
                 else:
                     log.info('PASSED:Ping6 to destination {0} succeeded'.format(destination))
             else:
                 log.info('Negative case')
                 if not re.search( ' 100.00% packet loss', ping_out, re.I ):
                     patstr='packet loss'
                     pattern='[ \t]+([0-9.%]+)[ \t]+{0}'.format(patstr)
                     pkt_loss=re.findall(pattern,ping_out, re.I)
                     testResult( 'fail', 'Ping6 to destination {0} on {1} DID NOT fail, Expected 100.00% packet loss but received {2} packet loss'.\
                     format( destination, hdl.switchName, utils.listtostr(pkt_loss)), log )
                 else:
                     log.info('PASSED:Ping6 to destination {0} failed on {1}'.format(destination, hdl.switchName))

class verifyPingFromLocalSources():
  "  verifyPingFromLocalSources - Method to verify ping to a list of destinations from all\
  the IP interfaces configured on the switch as source\
  \
  Mandatory Args\
  \
  hdl - icon switch object\
  log - harness/python logger object\
  dest_list - Comma separated list of IP addresses or host names\
  \
  Optional Args\
  \
  -packet_size - packet size to be used, default=64 bytes\
  -interval - time interval in sec between ping packets, default=0\
  -timeout - time value in secs for ping timeout, default=2 secs\
  -vrf - VRF name, default='default' vrf\
  -count - Number of ping packets to be used for verification, default=5\
  \
  Usage\
  \
  verifyPingFromLocalSources( hdl, log, dest_list )\
  verifyPingFromLocalSources( hdl, log, dest_list, '-packet_size 64 -interval 1 -vrf management -count 5')"
  def __init__(self, hdl, log, dest_list, *args ):
     self.result='pass'

     arggrammar={}
     arggrammar['packet_size']='-type int -default 64'
     arggrammar['interval']='-type int -default 0'
     arggrammar['timeout']='-type int -default 2'
     arggrammar['vrf']='-type str -default default'
     arggrammar['count']='-type int -default 5'
     ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
     destination_list=dest_list.split(',')

     intf_dict=utils.getIpv4InterfaceBriefDict( hdl, log, '-status up' )

     for destination in destination_list:
         for intf in intf_dict.keys():
             source=intf_dict[intf]['IP Address']
             cmd='ping {0} source {1} packet-size {2} interval {3} timeout {4} vrf {5} count {6}'.format(           \
                 destination, source, ns.packet_size, ns.interval, ns.timeout, ns.vrf, ns.count )

             log.info('Verifying ping to destination {0} with source {1}'.format(destination,source))
             ping_out=hdl.iexec(cmd)
             if not re.search( ' 0.00% packet loss', ping_out, re.I ):
                 ping_out_new=hdl.iexec(cmd)
                 if not re.search( ' 0.00% packet loss', ping_out_new, re.I ):
                     testResult( 'fail', 'Ping to destination {0} with source {1} failed, Expected 0.00% packet     \
                        loss but received {1}'.format( destination, source,  ping_out_new ), log )
                 else:
                     log.info('ping to destination {0} with source {1} succeeded'.format(destination,source))
             else:
                 log.info('ping to destination {0} with source {1} succeeded'.format(destination,source))







class verifyPing6FromLocalSources():
  "  verifyPing6FromLocalSources - Method to verify ping to a list of destinations from all\
  the IPv6 interfaces configured on the switch as source\
  \
  Mandatory Args\
  \
  hdl - icon switch object\
  log - harness/python logger object\
  dest_list - Comma separated list of IP addresses or host names\
  \
  Optional Args\
  \
  -packet_size - packet size to be used, default=64 bytes\
  -interval - time interval in sec between ping packets, default=0\
  -timeout - time value in secs for ping timeout, default=2 secs\
  -vrf - VRF name, default='default' vrf\
  -count - Number of ping packets to be used for verification, default=5\
  -interface - Mandatory when it is a link local address .\
  \
  Usage\
  \
  verifyPing6FromLocalSources( hdl, log, dest_list )\
  verifyPing6FromLocalSources( hdl, log, dest_list, '-packet_size 64 -interval 1 -vrf management -count 5 -interface vlan2')"
  def __init__(self, hdl, log, dest_list, *args ):
     self.result='pass'

     arggrammar={}
     arggrammar['packet_size']='-type int -default 64'
     arggrammar['interval']='-type int -default 0'
     arggrammar['timeout']='-type int -default 2'
     arggrammar['vrf']='-type str -default default'
     arggrammar['count']='-type int -default 5'
     ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
     destination_list=dest_list.split(',')

     intf_dict=utils.getIpv6InterfaceBriefDict( hdl, log, '-status up' )

     for destination in destination_list:
         for intf in intf_dict.keys():
             source=intf_dict[intf]['IPv6 Address']
             print('source', source)
             cmd='ping6 {0} source {1} packet-size {2} interval {3} timeout {4} vrf {5} count {6}'.format(         \
                 destination, source, ns.packet_size, ns.interval, ns.timeout, ns.vrf, ns.count )

             log.info('Verifying ping6 to destination {0} with source {1}'.format(destination,source))
             ping_out=hdl.iexec(cmd)
             if not re.search( ' 0.00% packet loss', ping_out, re.I ):
                ping_out_new=hdl.iexec(cmd)
                if not re.search( ' 0.00% packet loss', ping_out_new, re.I ):
                   testResult( 'fail', 'Ping6 to destination {0} with source {1} failed, Expected 0.00% packet     \
                       loss but received {1}'.format( destination, source,  ping_out_new ), log )
                else:
                   log.info('ping6 to destination {0} with source {1} succeeded'.format(destination,source))
             else:
                log.info('ping6 to destination {0} with source {1} succeeded'.format(destination,source))






class verifyPortChannels():
  "  verifyPortChannels - Method to verify L2/L3 PortChannels\
  \
  Mandatory args\
  \
  hdl - switch handle object from icon\
  log - harness/python logging object\
  \
  Optional args\
  \
  pc_list - Comma separated list of Port-channels\
  pc_dict - Dictionary with port-channel as key and 'Status' as the value\
  \
  Sample Usage:\
  verifyPortChannels( hdl, log )\
  verifyPortChannels( hdl, log, pc_list )\
  verifyPortChannels( hdl, log, pc_dict=<dict> )\
  "
  def __init__(self, hdl, log, *args, **pc_dict ):
     self.result='pass'
     arggrammar={}
     arggrammar['pc_list']='-type str'
     arggrammar['verify_iterations']='-type int -default 1'
     arggrammar['verify_interval']='-type int -default 5'
     parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
     verify_iterations=parse_output.verify_iterations
     verify_interval=parse_output.verify_interval

     # loopuntil logic begin - repeat verifiy port-channels until input iterations, \
     # with input interval as sleep after each iteration
     for iteration in range(verify_iterations):


         # Get list of port-channels configured on the switch
         pc_out_list=getPortChannelList(hdl,log)
    
         # If pc_list is given use it, otherwise get all port-channels configured
         if parse_output.pc_list:
            pc_list=parse_output.pc_list.split(',')
         else:
            pc_list=getPortChannelList(hdl,log)
    
         # Get Status of all Interfaces for PC status verification ..
         intf_dict=getInterfaceBriefDict( hdl, log )
    
         verify_result=True
         # If pc dict is given then ..
         if pc_dict:
            # Verify the status of each port-channels
            for pc_nam in pc_dict.keys():
                if pc_nam not in pc_out_list:
                    #testResult('fail','The port-channel given in the pc_dict {0} does not exist on the switch'.format( pc_nam), log)
                    log.info('The port-channel given in the pc_dict {0} does not exist on the switch'.format( pc_nam))
                    #continue
                    verify_result=False
                else:
                    if pc_nam not in intf_dict.keys():
                        #testResult('fail', 'Portchannel {0} is not in port-channel dict on the switch {1}'.format( pc_nam, hdl.switchName), log )        
                        log.info('Portchannel {0} is not in port-channel dict on the switch {1}'.format( pc_nam, hdl.switchName))        
                        verify_result=False
                    elif not re.search( pc_dict[pc_nam]['Status'], intf_dict[pc_nam]['Status'], flags=re.I ):
                        #testResult('fail', 'PortChannel Status not matching for PC {0}, Expected Status {1}, Actual status on the switch {2}'.format( pc_nam, pc_dict[pc_nam]['Status'], intf_dict[pc_nam][Status]), log )
                        log.info('PortChannel Status not matching for PC {0}, Expected Status {1}, Actual status on the switch {2}'.format( pc_nam, pc_dict[pc_nam]['Status'], intf_dict[pc_nam][Status]))
                        verify_result=False
                    else:
                        log.info('Portchannel {0} is in correct state {1}'.format(pc_nam, pc_dict[pc_nam]['Status']))
         else:
            # If dictionary not given ..
            for pc_nam in pc_list:
                if pc_nam not in intf_dict.keys():
                    #testResult('fail', 'Portchannel {0} is not in interface_dict on the switch {1}'.format( pc_nam, hdl.switchName), log )          
                    log.info('Portchannel {0} is not in interface_dict on the switch {1}'.format( pc_nam, hdl.switchName))          
                    verify_result=False
                elif not re.search( 'up', intf_dict[pc_nam]['Status'], re.I ):
                    #testResult('fail', 'Portchannel {0} is in down state, Expected Status {1}, Actual status on the switch {2}'.format( pc_nam, 'up', intf_dict[pc_nam]['Status']), log )
                    log.info('Portchannel {0} is in down state, Expected Status {1}, Actual status on the switch {2}'.format( pc_nam, 'up', intf_dict[pc_nam]['Status']))
                    verify_result=False
                else:
                    log.info('PortChannel {0} is in correct state - Up'.format(pc_nam))
         # exit logic for loop iterations, po is not up after expected iterations, or if po is up we exit
         if verify_result:
             testResult('pass','{0} : Portchannels {1} state verfications passed at iteration {2}'.format(hdl.switchName,pc_list,iteration),log)
             break
         elif iteration==verify_iterations-1:
             testResult('fail','{0} : Portchannels {1} state verfications failed in all iterations'.format(hdl.switchName,pc_list),log)
             break
 
         time.sleep(verify_interval)


class verifyPortChannelMembers():
  "  verifyPortChannelMembers - Method to verify L2/L3 PortChannelMembers\
  \
  Mandatory args\
  \
  hdl - switch handle object from icon\
  log - harness/python logging object\
  \
  Optional args\
  \
  pc_list - Comma separated list of Port-channels\
  pc_dict - Dictionary with port-channel as key and 'Status' as the value\
  \
  Sample Usage:\
  verifyPortChannelMembers( hdl, log)\
  verifyPortChannelMembers( hdl, log, pc_list )\
  verifyPortChannelMembers( hdl, log, pc_dict=<dict> )\
  "
  def __init__(self, hdl, log, *args, **pc_dict):
     self.result='pass'


     arggrammar={}
     arggrammar['pc_list']='-type str'
     parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

     # Get list of port-channels configured on the switch
     pc_out_list=getPortChannelList(hdl,log)

     # If pc_list is given use it, otherwise get all port-channels configured
     if parse_output.pc_list:
        pc_list=parse_output.pc_list.split(',')
     else:
        pc_list=getPortChannelList(hdl,log)

     # Get Status of all Interfaces for PC status verification ..
     intf_dict=getInterfaceBriefDict( hdl, log )

     
     # If pc dict is given then ..
     if pc_dict:
        # Verify the status of each port-channels
        for pc_nam in pc_dict.keys():
            if pc_nam not in pc_out_list:
                testResult('fail','The port-channel given in the pc_dict {0} does not exist on the                \
                   switch'.format( pc_nam), log)
                continue
            else:
                for pc_memb in pc_nam.keys():
                    if not re.search( pc_dict[pc_nam][pc_memb]['Status'], intf_dict[pc_memb]['Status'],           \
                        flags=re.I ):
                        testResult('fail', 'PortChannel Member Status not matching for PC {0} Member {1},         \
                           Expected Status {1}, Actual status on the switch {2}'.format( pc_nam, pc_memb,         \
                           pc_dict[pc_nam][pc_memb]['Status'], intf_dict[pc_memb]['Status']), log )
                    else:
                        log.info('Portchannel {0} member {1} is in expected state {2}'.format(pc_nam,           \
                           pc_dict[pc_nam][pc_memb]['Status'] ))
     # If dictionary not given ..
     else:
        for pc_nam in pc_list:
            pc_memb_list=getPortChannelMemberList( hdl, log,'-pc_nam {0}'.format(pc_nam))
            if not pc_memb_list:
                testResult('fail', 'Port channel member list is empty',log)
                self.result = 'fail'
                return
            for pc_memb in pc_memb_list:
                if normalizeInterfaceName(log,pc_memb) not in intf_dict:
                    testResult('fail','Portchannel Member {0} is NOT found in show interface brief'.format(pc_memb),log)
                elif not re.search( 'up', intf_dict[normalizeInterfaceName(log,pc_memb)]['Status'], re.I ):
                    testResult('fail', 'Portchannel Member {0} NOT up, Expected Status {1}, Actual status {2}, switch:{3}'\
                                   .format( pc_memb, 'up', intf_dict[normalizeInterfaceName(log,pc_memb)]['Status'],hdl.switchName),log )
                else:
                    log.info('PortChannel {0} is in correct state - Up'.format(pc_nam))



##########################################################


class verifyOspfNeighbor():

  def __init__(self,hdl, log, *args, **ospf_dict):
    self.result='pass'

    # Sample Usage:
    # verifyOspfNeighbor(hdl,log)
    # verifyOspfNeighbor(hdl,log, '-vrf default')
    # verifyOspfNeighbor(hdl,log, neighbor_list)
    # verifyOspfNeighbor(hdl,log, **neighbor_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbors']='-type str'
    arggrammar['iteration']='-type int -default 1'
    arggrammar['interval']='-type int -default 30'

    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
    
    for loop in range(parse_output.iteration):
        loopuntil_result='pass'  
    
        # Get the actual output from switch
        if parse_output.vrf:
            out_ospf_dict = getIpOspfNeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
        else:
            out_ospf_dict = getIpOspfNeighborDict(hdl,log)
        if parse_output.neighbors:
            neighbors=re.findall('('+rex.IPv4_ADDR+')',parse_output.neighbors)
        else:
            neighbors = []
        # All verification steps as below
        if ospf_dict:
            # The values from this dictionary will be verified against the values from get proc
            for nei in ospf_dict.keys():
                if (nei not in out_ospf_dict.keys()):
                    log.info('Attempt {0} of {1} - No Info for OSPF Neighbor:{2} on {3}'.\
                                    format(loop, parse_output.iteration, nei,out_ospf_dict[nei]['Interface']))
                    loopuntil_result='fail'
                    continue
                # Check Expected keys are in output keys , return fail if it's not,
                # check following lines otherwise
                for key in ospf_dict[nei].keys():
                    if key not in out_ospf_dict[nei].keys():
                        log.info('Attempt {0} of {1} - No Info for key:({2}) for OSPF Neighbor {3}'.\
                                        format(loop, parse_output.iteration, key,nei))
                        loopuntil_result='fail'
                        continue
                    #To Do exact match
                    if (ospf_dict[nei][key] == out_ospf_dict[nei][key]):
                        log.info('OSPF Neighbor:{0} has value {1} for {2}'.\
                                        format(nei,out_ospf_dict[nei][key],key))
                    else:
                        log.info('Attempt {0} of {1} - OSPF Neighbor:{2} has value {3} for {4}'.\
                                        format(loop, parse_output.iteration, nei,out_ospf_dict[nei][key],key))
                        loopuntil_result='fail'
        if neighbors:
            # Neighbors will be tested in this section to make sure they are in FULL state
            for nei in neighbors:
                if (nei not in  out_ospf_dict.keys()):
                    # If this is not in output then fail cases
                    log.info('Attempt {0} of {1} - OSPF Neighbor:{2} NOT in OSPF neighbor list'.format(loop, parse_output.iteration, nei))
                    loopuntil_result='fail'
                else:
                    # Go through list of all neighbors and make sure it's in FULL state
                    if (out_ospf_dict[nei]['Adj'] == 'FULL'):
                        log.info('OSPF Neighbor:{0} in FULL State on {1}'.\
                                        format(nei,out_ospf_dict[nei]['Interface']))
                    else:
                        log.info('Attempt {0} of {1} - OSPF Neighbor:{2} NOT in FULL State on {3}'.\
                                        format(loop, parse_output.iteration, nei,out_ospf_dict[nei]['Interface']))
                        loopuntil_result='fail'
        if (not neighbors) and (not ospf_dict):
            # Verify all neighbors are in FULL State, verification assumes right Adj is FULL state
            for nei in out_ospf_dict.keys():
                if (out_ospf_dict[nei]['Adj'] == 'FULL'):
                    log.info('OSPF Neighbor:{0} in FULL State on {1}'.\
                                    format(nei,out_ospf_dict[nei]['Interface']))
                else:
                    log.info('Attempt {0} of {1} - OSPF Neighbor:{2} NOT in FULL State on {3}'.\
                                    format(loop, parse_output.iteration, nei,out_ospf_dict[nei]['Interface']))
                    loopuntil_result='fail'


        if loopuntil_result=='pass':
            break
        if loop==parse_output.iteration-1:
            self.result='fail'
        else:
            time.sleep(parse_output.interval)

    if self.result=='pass':
        testResult('pass','Ospf Neighbor verification passed on {0}'.format(hdl.switchName), log)
    else:
        testResult('fail','Ospf Neighbor verification failed on {0}'.format(hdl.switchName), log)







##########################################################

class  verifyOspfv3Neighbor():
  def __init__(self,hdl, log, *args, **ospfv3_dict):
    self.result='pass'
    # Sample Usage:
    # verifyOspfv3Neighbor(hdl,log)
    # verifyOspfv3Neighbor(hdl,log, '-vrf default')
    # verifyOspfv3Neighbor(hdl,log, '-interface eth3/1')
    # verifyOspfv3Neighbor(hdl,log, value=ospfv3_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['interface']='-type str'
    arggrammar['mutualExclusive'] =[('vrf','interface')]
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_ospfv3_dict = getOspfv3NeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_ospfv3_dict = getOspfv3NeighborDict(hdl,log)
    if parse_output.interface:
        interface=re.findall('('+rex.INTERFACE_NAME+')',parse_output.interface)
        intf=listtostr(interface)
        intf=normalizeInterfaceName(log,intf)
    else:
        interface = []

    # All verification steps as below
    if ospfv3_dict:
        ospfv3_dict = ospfv3_dict['value']
        # The values from this dictionary will be verified against the values from get proc
        for intf in ospfv3_dict.keys():
            if (intf not in out_ospfv3_dict.keys()):
                testResult('fail','No Info for OSPF Interface:{0}'.\
                                format(intf),log)
                continue
            # Check Expected keys are in output keys , return fail if it's not,
            # check following lines otherwise
            for key in ospfv3_dict[intf].keys():
                if key not in out_ospfv3_dict[intf].keys():
                    testResult('fail','No Info for OSPFv3 Interface {0}'.\
                                    format(intf),log)
                    continue
                #To Do exact match
                if (ospfv3_dict[intf][key] == out_ospfv3_dict[intf][key]):
                    testResult('pass','OSPFv3 Interface:{0} has value {1} for {2}'.\
                                    format(intf,out_ospfv3_dict[intf][key],key),log)
                else:
                    testResult('fail','OSPFv3 Interface:{0} has value {1} for {2}'.\
                                    format(intf,out_ospfv3_dict[intf][key],key),log)
    if interface:
        # Neighbors will be tested in this section to make sure they are in FULL state
            keys = getKeys(intf,out_ospfv3_dict.keys())
            if not keys:
                testResult('fail','Interface {0} not in ospfv3 neighbor dict on {1}'.format(intf, hdl.switchName), log)
            for key in keys:
                if (out_ospfv3_dict[key]['State'] == 'FULL'):
                      #testResult('pass','OSPFv3 Interface:{0} in FULL State'.\
                      #             format(key),log)
                      log.info('OSPFv3 Interface:{0} in FULL State'.\
                                   format(key))
                else:
                      testResult('fail','OSPFv3 Interface:{0} NOT in FULL State'.\
                                   format(key),log)

    if (not interface) and (not ospfv3_dict):
        # Verify all neighbors are in FULL State, verification assumes right Adj is FULL state
        for intf in out_ospfv3_dict.keys():
            if (out_ospfv3_dict[intf]['State'] == 'FULL'):
                #testResult('pass','OSPFv3 Interface:{0} in FULL State'.\
                #                format(intf),log)
                log.info('OSPFv3 Interface:{0} in FULL State'.\
                                format(intf))
            else:
                testResult('fail','OSPFv3 Interface:{0} NOT in FULL State'.\
                                format(intf),log)



#======================================================================================#
# verifyVrfState - Method to verify the state of Vrfs
#       
# mandatory args: hdl, log
#       
# Optional args: vrf or list of vrfs, vrf dict
#      Usage Examples: verifyVrfState(hdl, log)
#                       verifyVrfState(hdl, log, **vrfdict)
#                       verifyVrfState(hdl, log, '-vrf '+str(vrflist))
#======================================================================================#


class verifyVrfState():
  "  verifyVrfState - Method to verify the state of Vrfs\
  \
  mandatory args: hdl, log\
  \
  Optional args: vrf or list of vrfs, vrf dict\
  Usage Examples: verifyVrfState(hdl, log)\
                         verifyVrfState(hdl, log, **vrfdict)\
                         verifyVrfState(hdl, log, '-vrf '+str(vrflist))"
  def __init__(self,hdl, log, *args, **vrf_dict):
    self.result='pass'
    arggrammar={}
    arggrammar['vrf']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    out_vrf_dict=getVrfDict(hdl, log)
    vrf_list=[]

    if hasattr(parse_output, 'vrf'):
        pat=(rex.VRF_NAME)
        vrf_list=re.findall( pat, parse_output.vrf)
        #Verify vrfs in the list are all in Up state
        for vrfname in vrf_list:
            if (vrfname not in out_vrf_dict.keys()):
                testResult('fail','No Info for vrf:{0}'.format(vrfname),log)
                continue
            elif str(out_vrf_dict[vrfname]['State'])=='Up':
                testResult('pass','Vrf {0} State is Up'.format(vrfname),log)
            else:
                testResult('fail','Vrf {0} not up'.format(vrfname),log)
    if vrf_dict:
        # The values from this dictionary will be verified against the values from get proc
        # Check Expected keys are in output keys , return fail if it's not,
        for vrfname in vrf_dict.keys():
            if (vrfname not in out_vrf_dict.keys()):
                testResult('fail','No Info for vrf:{0}'.format(vrfname),log)
                continue
            elif str(out_vrf_dict[vrfname]['State'])==str(vrf_dict[vrfname]['State']):
                testResult('pass','Vrf {0} State is {1}'.format(vrfname, out_vrf_dict[vrfname]['State']),log)
            else:
                testResult('fail','Vrf {0} State is {1}'.format(vrfname, out_vrf_dict[vrfname]['State']),log)

    if (not vrf_list) and (not vrf_dict):
        # Verify all vrfs are in Up state
        for vrfname in out_vrf_dict.keys():
            if str(out_vrf_dict[vrfname]['State'])=='Up':
                    testResult('pass','Vrf {0} State is Up'.format(vrfname),log)
            else:
                    testResult('fail','Vrf {0} not up'.format(vrfname),log)



class verifyVlans():
  "  verifyVlans - Method to verify the state of Vlans\
  \
  mandatory args: hdl, log\
  \
  Optional args: vlan or list of vlans, vlan dict (Dict iformat s same as getVlanDict)\
  Usage Examples: verifyVlans(hdl, log) - Verifies all vlans are active\
  verifyVlans(hdl, log, **vlandict) - Verifies against vlandict\
  verifyVlans(hdl, log, '-vlans 1,20,91-100')"
  def __init__(self,hdl, log, *args, **vlandict):
    self.result='pass'
    arggrammar={}
    arggrammar['vlans']='-type str'
    arggrammar['status']='-type str -default active'
    arggrammar['iterations']='-type int -default 1'
    arggrammar['interval']='-type int -default 5'
    cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    showvlanbriefdict=getVlanDict(hdl, log)
    print ('%%%%% VLAN DICT is : {0}'.format(showvlanbriefdict))
    if cmdnamespace.vlans:
      for iteration in range(cmdnamespace.iterations):
        verified=True
        for vlan in utils.strtoexpandedlist(cmdnamespace.vlans,True):
                if (str(vlan) not in showvlanbriefdict.keys()):
                    verified=False
                    log.info('iteration {0} Expected: Some info for vlan:{1} Actual: No Info for vlan:{1}'.format(iteration+1,vlan))
                    #testResult('fail','Expected: Some info for vlan:{0} Actual: No Info for vlan:{0}'.format(vlan),log)
                    continue
                elif str(showvlanbriefdict[str(vlan)]['Status'])==cmdnamespace.status:
                    log.info('iteration {0} Vlan {1} Status is {2}'.format(iteration+1,vlan,cmdnamespace.status))
                    #testResult('pass','Vlan {0} Status is active'.format(vlan),log)
                else:
                    verified=False
                    log.info('iteration {0} Expected: Vlan {1} Status is active Actual: Status is {2}'.format(iteration+1,vlan,showvlanbriefdict[str(vlan)]['Status']))
                    #testResult('fail','Expected: Vlan {0} Status is active Actual: Status is {1}'.format(vlan,showvlanbriefdict[str(vlan)]['Status']),log)
        if verified or iteration == cmdnamespace.iterations-1:
            break
        else:
            log.info("Waiting for {0} seconds for next iteration".format(cmdnamespace.interval))
            time.sleep(cmdnamespace.interval)

      if verified:
        testResult('pass','All vlans are  in expected state',log)
      else:
        testResult('fail','Some vlans are  in expected state',log)
    if vlandict:
      for iteration in range(cmdnamespace.iterations):
        verified=True
        if compareVars(vlandict,showvlanbriefdict,log):
            log.info('iteration {0} {1} is subset of {2}'.format(iteration+1,vlandict,showvlanbriefdict))
            #testResult('pass','{0} is subset of {1}'.format(vlandict,showvlanbriefdict),log)
        else:
            verified=False
            log.info('iteration {0} {1} is not subset of {2}'.format(iteration+1,vlandict, showvlanbriefdict))
            #testResult('fail','{0} is not subset of {1}'.format(vlandict, showvlanbriefdict),log)
        if verified or iteration == cmdnamespace.iterations-1:
            break
        else:
            log.info("Waiting for {0} seconds for next iteration".format(cmdnamespace.interval))
            time.sleep(cmdnamespace.interval)
      if verified:
          testResult('pass','All vlans are  in expected state',log)
      else:
          testResult('fail','Some vlans are  in expected state',log)

    if (not cmdnamespace.vlans) and (not vlandict):
      for iteration in range(cmdnamespace.iterations):
        verified=True
        # Verify all VLANs are in active state
        for vlan in showvlanbriefdict.keys():
            if str(showvlanbriefdict[vlan]['Status'])=='active':
                    log.info('iteration {0} Vlan {1} Status is active'.format(iteration+1,vlan))
                    #testResult('pass','Vlan {0} Status is active'.format(vlan),log)
            else:
                    verified=False
                    log.info('iteration {0} Expected: Vlan{1} is active Actual: Vlan {2} not active'.format(iteration+1,vlan))
                    #testResult('fail','Expected: Vlan{0} is active Actual: Vlan {0} not active'.format(vlan),log)
        if not len(showvlanbriefdict.keys()):
            verified=False
            log.info('iteration {0} Expected: atleast one vlan to be active Actual: No vlans found'.format(iteration+1))
            #testResult('fail','Expected: atleast one vlan to be active Actual: No vlans found',log)
        if verified or iteration == cmdnamespace.iterations-1:
            break
        else:
            log.info("Waiting for {0} seconds for next iteration".format(cmdnamespace.interval))
            time.sleep(cmdnamespace.interval)
      if verified:
          testResult('pass','All vlans are  in expected state',log)
      else:
          testResult('fail','Some vlans are  in expected state',log)

class verifySwitchportAccessVlan():
    ''' Class to verify switchport access vlan on the given interface  
    mandatory args: hdl, log, port. input ports can be a list, range or any combination
    Usage Examples: 
    obj=verifySwitchportAccessVlan(hdl,log,'-ports eth1/9,eth1/1 -vlans 993')'''

    def __init__(self, hdl, log, *args):
        self.result='pass'
        self.log=log
        self.hdl=hdl
        arggrammar={}
        arggrammar['vlans']='-type str -required true'
        arggrammar['ports']='-type str -required true'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.ports=strtoexpandedlist(ns.ports)
        self.vlans=ns.vlans
        for port in self.ports:
            vlan=getInterfaceSwitchportDict(hdl,log, '-interface {0}'.format(port))
            if 'Access Mode VLAN' not in vlan.keys():
                testResult('fail','{0} {1} on port {2} failed '\
                           .format(self.__class__.__name__,self.vlans,self.ports),self.log)
                return    
            elif vlan['Access Mode VLAN']==self.vlans:
                self.log.info(' {0} {1} on port {2} success '\
                              .format(self.__class__.__name__,self.vlans,self.ports))
            else:
                self.log.info(' port {0} not in expected  access vlan {1} '.format(port,self.vlans))
                self.log.info(' instead port {0} observed in access vlan {1} '.format(port,vlan['Access Mode VLAN']))
                testResult('fail','{0} {1} on port {2} failed '\
                           .format(self.__class__.__name__,self.vlans,self.ports),self.log)
                return

class verifySwitchportOperMode():
    ''' Class to verify operational switchport mode on the given interface : access or trunk
    mandatory args: hdl, log, port, mode. 
    - ports : input port can be a list, range or any combination
    - sw_oper_mode : should be 'access' or 'trunk' 
    Usage Examples: 
    obj=verifySwitchportOperMode(hdl,log,'-ports eth1/9,eth1/1 -sw_oper_mode access')'''

    def __init__(self, hdl, log, *args):
        self.result='pass'
        self.log=log
        self.hdl=hdl
        arggrammar={}
        arggrammar['ports']='-type str -required true'
        arggrammar['sw_oper_mode']='-type str -required true'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.ports=strtoexpandedlist(ns.ports)
        self.oper_mode=ns.sw_oper_mode
        for port in self.ports:
            status=getInterfaceSwitchportDict(hdl,log, '-interface {0}'.format(port))
            if 'Operational Mode' not in status.keys():
                testResult('fail','Switchport not enabled on interface {0}'\
                           .format(port),self.log)
                return                
            elif status['Operational Mode']==self.oper_mode:
                self.log.info(' {0} {1} on port {2} success '\
                              .format(self.__class__.__name__,self.oper_mode,port))
            else:
                self.log.info(' port {0} not in expected {1}  mode'.format(port,self.oper_mode))
                self.log.info(' instead port {0} was oberseved in {1}  mode'.format(port,status['Operational Mode']))
                testResult('fail','{0} access on port {1} failed '\
                           .format(self.__class__.__name__,port),self.log)
                return

class verifySwitchportInfo():
    ''' Class to verify all switchport related info which are configurable
    mandatory args: hdl, log, port. 
    - ports : input port can be a list, range or any combination
    optional args:
    -switchport : values - Enabled or Disabled
    -oper_mode : values - access or trunk 
    -access_vlan : vlan 
    -trk_allowed_vlan : vlan or vlan list or range 
    -trk_native_vlan : vlan 
    -trk_allowed_vlan_none : none 
    -trk_allowed_vlan_all : 1-4094 
    Usage Examples: 
    obj=verifySwitchportInfo(hdl,log,'-ports eth3/4 -switchport Enabled -oper_mode trunk \
                                      -trk_allowed_vlan 1-201 -trk_native_vlan 200')
    obj=verifySwitchportInfo(hdl,log,'-ports eth3/6 -switchport Enabled -oper_mode access \
                                      -access_vlan 5')'''

    def __init__(self, hdl, log, *args):
        self.result='pass'
        self.log=log
        self.hdl=hdl
        arggrammar={}
        arggrammar['ports']='-type str -required true'
        arggrammar['switchport']='-type str -choices Enabled,Disabled'
        arggrammar['oper_mode']='-type str -choices access,trunk,pvlan_promisc,pvlan_host'
        arggrammar['access_vlan']='-type str'
        arggrammar['trk_allowed_vlan']='-type str'
        arggrammar['trk_allowed_vlan_none']='-type str -choices none'
        arggrammar['trk_allowed_vlan_all']='-type str -choices 1-4094'
        arggrammar['trk_native_vlan']='-type str'
        arggrammar['pvlan_primary']='-type str'
        arggrammar['pvlan_secondary']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.ports=strtoexpandedlist(ns.ports)
        self.switchport=ns.switchport
        self.oper_mode=ns.oper_mode
        self.access_vlan=ns.access_vlan
        self.trk_allowed_vlan=ns.trk_allowed_vlan
        self.trk_allowed_vlan_none=ns.trk_allowed_vlan_none
        self.trk_allowed_vlan_all=ns.trk_allowed_vlan_all
        self.trk_native_vlan=ns.trk_native_vlan
        self.pvlan_primary=ns.pvlan_primary
        self.pvlan_secondary=ns.pvlan_secondary
        for port in self.ports:
            # get interface switchport info dict with all params 
            portinfo=getInterfaceSwitchportDict(hdl,log, '-interface {0}'.format(port))
            self.log.debug('%% get interface switchport dict value : {0}'.format(portinfo))
            if self.switchport:
                if 'Switchport' not in portinfo:
                    testResult('fail','{0} Switchport info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                # verify switchport enabled or disabled on the port 
                if portinfo['Switchport']==self.switchport: 
                    self.log.info(' {0} switchport {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.switchport,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                         .format(self.__class__.__name__,port,self.switchport,portinfo['Switchport']))
                    testResult('fail','{0} on port {1} failed for switchport enabled disabled info '\
                               .format(self.__class__.__name__,port,self.switchport),self.log)
                    return
            if self.oper_mode:
                if 'Operational Mode' not in portinfo:
                    testResult('fail','{0} Operational Mode info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                if self.oper_mode=='pvlan_promisc':
                    self.oper_mode='Private-vlan promiscuous'
                if self.oper_mode=='pvlan_host':
                    self.oper_mode='Private-vlan host'
                # verify switchport operational mode access or trunk 
                if portinfo['Operational Mode']==self.oper_mode:
                    self.log.info(' {0} oper_mode {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.oper_mode,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                         .format(self.__class__.__name__,port,self.oper_mode,portinfo['Operational Mode']))
                    testResult('fail','{0} on port {1} failed for operational mode info '\
                               .format(self.__class__.__name__,port),self.log)
                    return
    
            if self.access_vlan:
                if 'Access Mode VLAN' not in portinfo:
                    testResult('fail','{0} Access Mode VLAN info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                # verify switchport access vlan on port
                if portinfo['Access Mode VLAN']==self.access_vlan:
                    self.log.info(' {0} access_vlan {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.access_vlan,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                         .format(self.__class__.__name__,port,self.access_vlan,portinfo['Access Mode VLAN']))
                    testResult('fail','{0} on port {1} failed for acess vlan info '\
                               .format(self.__class__.__name__,port),self.log)
                    return
    
            if self.trk_native_vlan:
                if 'Trunking Native Mode VLAN' not in portinfo:
                    testResult('fail','{0} Trunking Native Mode VLAN info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                # verify switchport trunk native vlan on port  
                if portinfo['Trunking Native Mode VLAN']==self.trk_native_vlan:
                    self.log.info(' {0} trk_native_vlan {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.trk_native_vlan,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                       .format(self.__class__.__name__,port,self.trk_native_vlan,portinfo['Trunking Native Mode VLAN']))
                    testResult('fail','{0} on port {1} failed for trunk native vlan info '\
                               .format(self.__class__.__name__,port),self.log)
                    return
    
            if self.trk_allowed_vlan:
                if 'Trunking VLANs Allowed' not in portinfo:
                    testResult('fail','{0} Trunking VLANs Allowed info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                # verify switchport allowed vlan 
                if portinfo['Trunking VLANs Allowed']==utils.listtostr(shortenedList(utils.strtolist(self.trk_allowed_vlan))):
                    self.log.info(' {0} trk_allowed_vlan {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.trk_allowed_vlan,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                       .format(self.__class__.__name__,port,self.trk_allowed_vlan,portinfo['Trunking VLANs Allowed']))
                    testResult('fail','{0} on port {1} failed for trunk allowed vlan info '\
                               .format(self.__class__.__name__,port),self.log)
                    return
    
            elif self.trk_allowed_vlan_none:
                if 'Trunking VLANs Allowed' not in portinfo:
                    testResult('fail','{0} Trunking VLANs Allowed info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                # verify switchport allowed vlan none  - value is 'none' as displayed
                if portinfo['Trunking VLANs Allowed']==self.trk_allowed_vlan_none:
                    self.log.info(' {0} trk_allowed_vlan {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.trk_allowed_vlan_none,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                       .format(self.__class__.__name__,port,self.trk_allowed_vlan_none,portinfo['Trunking VLANs Allowed']))
                    testResult('fail','{0} on port {1} failed for trunk allowed vlan none info '\
                               .format(self.__class__.__name__,port),self.log)
                    return
    
            elif self.trk_allowed_vlan_all:
                if 'Trunking VLANs Allowed' not in portinfo:
                    testResult('fail','{0} Trunking VLANs Allowed info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                # verify switchport allowed vlan all - values 1-4094 
                if portinfo['Trunking VLANs Allowed']==self.trk_allowed_vlan_all:
                    self.log.info(' {0} trk_allowed_vlan {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.trk_allowed_vlan_all,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                       .format(self.__class__.__name__,port,self.trk_allowed_vlan_all,portinfo['Trunking VLANs Allowed']))
                    testResult('fail','{0} on port {1} failed for trunk allowed vlan all info '\
                               .format(self.__class__.__name__,port),self.log)
                    return

            if self.pvlan_secondary:
                if 'Operational Mode' not in portinfo:
                    testResult('fail','{0} Could not determine PVLAN mode for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                if portinfo['Operational Mode']=='Private-vlan promiscuous':
                    pvlan_secondary_title='Administrative private-vlan secondary mapping'
                if portinfo['Operational Mode']=='Private-vlan host':
                    pvlan_secondary_title='Administrative private-vlan secondary host-association'

                if pvlan_secondary_title not in portinfo:
                    testResult('fail','{0} Secondary vlan info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                pvlan_secondary_vlans_output_list=strtolist(portinfo[pvlan_secondary_title])
                pvlan_secondary_vlans_configured_list=strtolist(self.pvlan_secondary)
                if compareVars(pvlan_secondary_vlans_configured_list,pvlan_secondary_vlans_output_list,log) == "pass":
                    self.log.info(' {0} pvlan_secondary {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.pvlan_secondary,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                       .format(self.__class__.__name__,port,self.pvlan_secondary,portinfo[pvlan_secondary_title]))
                    testResult('fail','{0} on port {1} failed for pvlan secondary vlan info '\
                               .format(self.__class__.__name__,port),self.log)
                    return
    
            if self.pvlan_primary:
                if 'Operational Mode' not in portinfo:
                    testResult('fail','{0} Could not determine PVLAN mode for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                if portinfo['Operational Mode']=='Private-vlan promiscuous':
                    pvlan_primary_title='Administrative private-vlan primary mapping'
                if portinfo['Operational Mode']=='Private-vlan host':
                    pvlan_primary_title='Administrative private-vlan primary host-association'

                if pvlan_primary_title not in portinfo:
                    testResult('fail','{0} primary vlan info unavailable for port {1}'\
                        .format(self.__class__.__name__,port),self.log)
                    return
                if portinfo[pvlan_primary_title]==self.pvlan_primary:
                    self.log.info(' {0} pvlan_primary {1} on port {2} passed '\
                                  .format(self.__class__.__name__,self.pvlan_primary,port))
                else:
                    self.log.info(' {0} on port {1} expected : {2}, observed : {3}'\
                       .format(self.__class__.__name__,port,self.pvlan_primary,portinfo[pvlan_primary_title]))
                    testResult('fail','{0} on port {1} failed for pvlan primary vlan info '\
                               .format(self.__class__.__name__,port),self.log)
                    return

    
class verifyLinecards():
  "  verifyLinecards - Method to verify the state of line cards\
  \
  mandatory args: hdl, log\
  \
  Optional args: linecardss or list of linecards, linecard dict (Dict iformat s same as getLineCardDict)\
  Usage Examples: verifyLinecards(hdl, log) - Verifies all Linecardss are active\
  verifyLinecards(hdl, log, **lcdict) - Verifies against linecarddict\
  verifyLinecardss(hdl, log, '-linecards 1,3,4')"
  def __init__(self,hdl, log, *args, **linecarddict):
    self.result='pass'

    arggrammar={}
    arggrammar['linecards']='-type str'
    arggrammar['iterations']='-type int -default 1'
    arggrammar['interval']='-type int -default 30'
    cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if cmdnamespace.linecards:
        for iteration in range(cmdnamespace.iterations):
          showlcdict=getLineCardDict(hdl, log)
          result=True
          for lc in strtoexpandedlist(cmdnamespace.linecards):
            if (str(lc) not in showlcdict.keys()):
                log.info('Iteration {0} Expected: Some info for line card:{1} Actual: No Info for line card:{1}'.format(iteration+1,lc))
                result=False
                continue
            elif str(showlcdict[str(lc)]['Status']) in ['ok','active','standby']:
                log.info('Iteration {0} lc {1} Status is ok'.format(iteration+1,lc))
            else:
                log.info('Iteration {0} Expected: lc {1} Status is ok Actual: Status is {2}'.format(iteration+1,lc,showlcdict[str(lc)]['Status']))
                result=False
          if result or iteration == cmdnamespace.iterations-1:
              break
          else:
              log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
              time.sleep(cmdnamespace.interval)
        if result:
            testResult('pass','line card Status for line cards {0} is  ok'.format(cmdnamespace.linecards),log)
        else:
            testResult('fail','line card Status for some or all of the line cards {0} is not ok'.format(cmdnamespace.linecards),log)

    if linecarddict:
      for iteration in range(cmdnamespace.iterations):
        showlcdict=getLineCardDict(hdl, log)
        result=True
        if compareVars(linecarddict,showlcdict,log) == "pass":
              log.info('Iteration {0} All line cards in expected output {1} is available in actual output {2}'.format(iteration+1,linecarddict,showlcdict))
        else:
              log.info('Iteration {0} line cards in expected output {1} doesnt match with actual output {2}'.format(iteration+1,linecarddict,showlcdict))
              result=False
        if result or iteration == cmdnamespace.iterations-1:
          break
        else:
          log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
          time.sleep(cmdnamespace.interval)
      if result:
          testResult('pass','All line cards in expected output {0} is available in actual output {1}'.format(linecarddict,showlcdict),log)
      else:
          testResult('fail','line cards in expected output {0} doesnt match with actual output {1}'.format(linecarddict,showlcdict),log)

    if (not cmdnamespace.linecards) and (not linecarddict):
      for iteration in range(cmdnamespace.iterations):
        # Verify all Line cards are ok
        showlcdict=getLineCardDict(hdl, log)
        result=True
        for lc in showlcdict.keys():
            if str(showlcdict[lc]['Status']) in ['ok','active']:
                log.info('Iteration {0} Line card {1} Status is ok'.format(iteration+1,lc))
            else:
                log.info('Iteration {0} Expected: Line card {1} is ok Actual: Line card {1} not ok'.format(iteration+1,lc))
                result=False
        if not len(showlcdict.keys()):
            log.info('Expected: atleast one line card to be ok Actual: No line card found')
            result=False
        if result or iteration == cmdnamespace.iterations-1:
           break
        else:  
           log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
           time.sleep(cmdnamespace.interval)
      if result:
           testResult('pass','Line card status for {0} line cards is ok'.format(showlcdict.keys()),log)
      else:
           testResult('fail','Some or all of the line cards is not ok',log)




class verifySystemcards():
  "  verifySystemCards - Method to verify the state of System cards\
  \
  mandatory args: hdl, log\
  \
  Optional args: systemcards or list of systemcards, systemcard dict (Dict iformat s same as getSystemCardDict)\
  Usage Examples: verifySystemcards(hdl, log) - Verifies all System cards are active\
  verifySystemcards(hdl, log, **systemcarddict) - Verifies against systemccarddict\
  verifySystemcards(hdl, log, '-systemcards 1,3,4')"
  def __init__(self,hdl, log, *args, **systemcarddict):
    self.result='pass'

    arggrammar={}
    arggrammar['systemcards']='-type str'
    arggrammar['iterations']='-type int -default 1'
    arggrammar['interval']='-type int -default 60'
    cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if cmdnamespace.systemcards:
        for iteration in range(cmdnamespace.iterations):
          showlcdict=getSystemCardDict(hdl, log)
          result=True
          for lc in strtoexpandedlist(cmdnamespace.systemcards):
            if (str(lc) not in showlcdict.keys()):
                log.info('Iteration {0} Expected: Some info for System card:{1} Actual: No Info for System card:{1}'.format(iteration+1,lc))
                result=False
                continue
            elif str(showlcdict[str(lc)]['Status']) in ['ok','active','standby']:
                log.info('Iteration {0} system card {1} Status is ok'.format(iteration+1,lc))
            else:
                log.info('Iteration {0} Expected: system card {1} Status is ok Actual: Status is {2}'.format(iteration+1,lc,showlcdict[str(lc)]['Status']))
                result=False
          if result or iteration == cmdnamespace.iterations-1:
              break
          else:
              log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
              time.sleep(cmdnamespace.interval)
        if result:
            testResult('pass','system card Status for system cards {0} is  ok'.format(cmdnamespace.systemcards),log)
        else:
            testResult('fail','system card Status for some or all of the system cards {0} is not ok'.format(cmdnamespace.systemcards),log)

    if systemcarddict:
      for iteration in range(cmdnamespace.iterations):
        showlcdict=getSystemCardDict(hdl, log)
        result=True
        if compareVars(systemcarddict,showlcdict,log) == "pass":
              log.info('Iteration {0} All System cards in expected output {1} is available in actual output {2}'.format(iteration+1,systemcarddict,showlcdict))
        else:
              log.info('Iteration {0} System cards in expected output {1} doesnt match with actual output {2}'.format(iteration+1,systemcarddict,showlcdict))
              result=False
        if result or iteration == cmdnamespace.iterations-1:
          break
        else:
          log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
          time.sleep(cmdnamespace.interval)
      if result:
          testResult('pass','All System cards in expected output {0} is available in actual output {1}'.format(systemcarddict,showlcdict),log)
      else:
          testResult('fail','System cards in expected output {0} doesnt match with actual output {1}'.format(systemcarddict,showlcdict),log)

    if (not cmdnamespace.systemcards) and (not systemcarddict):
      for iteration in range(cmdnamespace.iterations):
        showlcdict=getSystemCardDict(hdl, log)
        result=True
        for lc in showlcdict.keys():
            if str(showlcdict[lc]['Status']) in ['ok','active']:
                log.info('Iteration {0} System card {1} Status is ok'.format(iteration+1,lc))
            else:
                log.info('Iteration {0} Expected: System card {1} is ok Actual: System card {2} not ok'.format(iteration+1,lc))
                result=False
        if not len(showlcdict.keys()):
            log.info('Expected: atleast one System card to be ok Actual: No system card found')
            result=False
        if result or iteration == cmdnamespace.iterations-1:
           break
        else:  
           log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
           time.sleep(cmdnamespace.interval)
      if result:
           testResult('pass','System card status for {0} System cards is ok'.format(showlcdict.keys()),log)
      else:
           testResult('fail','Some or all of the System cards is not ok',log)



class verifyFabriccards():
  "  verifyFabricards - Method to verify the state of Fabric cards\
  \
  mandatory args: hdl, log\
  \
  Optional args: fabriccards or list of fabriccards, fabriccard dict (Dict iformat s same as getFabricCardDict)\
  Usage Examples: verifyFabriccards(hdl, log) - Verifies all Fabric cards are active\
  verifyFabriccards(hdl, log, **fabriccarddict) - Verifies against fabricccarddict\
  verifyFabriccards(hdl, log, '-fabriccards 1,3,4')"
  def __init__(self,hdl, log, *args, **fabriccarddict):
    self.result='pass'

    arggrammar={}
    arggrammar['fabriccards']='-type str'
    arggrammar['iterations']='-type int -default 1'
    arggrammar['interval']='-type int -default 30'
    cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if cmdnamespace.fabriccards:
        for iteration in range(cmdnamespace.iterations):
          showlcdict=getFabricCardDict(hdl, log)
          result=True
          for lc in strtoexpandedlist(cmdnamespace.fabriccards):
            if (str(lc) not in showlcdict.keys()):
                log.info('Iteration {0} Expected: Some info for Fabric card:{1} Actual: No Info for Fabric card:{1}'.format(iteration+1,lc))
                result=False
                continue
            elif str(showlcdict[str(lc)]['Status']) in ['ok','active']:
                log.info('Iteration {0} fabric card {1} Status is ok'.format(iteration+1,lc))
            else:
                log.info('Iteration {0} Expected: Fabric card {1} Status is ok Actual: Status is {2}'.format(iteration+1,lc,showlcdict[str(lc)]['Status']))
                result=False
          if result or iteration == cmdnamespace.iterations-1:
              break
          else:
              log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
              time.sleep(cmdnamespace.interval)
        if result:
            testResult('pass','Fabric card Status for Fabric cards {0} is  ok'.format(cmdnamespace.fabriccards),log)
        else:
            testResult('fail','Fabric card Status for some or all of the Fabric cards {0} is not ok'.format(cmdnamespace.fabriccards),log)

    if fabriccarddict:
      for iteration in range(cmdnamespace.iterations):
        showlcdict=getFabricCardDict(hdl, log)
        result=True
        if compareVars(fabriccarddict,showlcdict,log) == "pass":
              log.info('Iteration {0} All Fabric cards in expected output {1} is available in actual output {2}'.format(iteration+1,fabriccarddict,showlcdict))
        else:
              log.info('Iteration {0} Fabric cards in expected output {1} doesnt match with actual output {2}'.format(iteration+1,fabriccarddict,showlcdict))
              result=False
        if result or iteration == cmdnamespace.iterations-1:
          break
        else:
          log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
          time.sleep(cmdnamespace.interval)
      if result:
          testResult('pass','All Fabric cards in expected output {0} is available in actual output {1}'.format(fabriccarddict,showlcdict),log)
      else:
          testResult('fail','Fabric cards in expected output {0} doesnt match with actual output {1}'.format(fabriccarddict,showlcdict),log)

    if (not cmdnamespace.fabriccards) and (not fabriccarddict):
      for iteration in range(cmdnamespace.iterations):
        showlcdict=getFabricCardDict(hdl, log)
        result=True
        for lc in showlcdict.keys():
            if str(showlcdict[lc]['Status']) in ['ok','active']:
                log.info('Iteration {0} Fabric card {1} Status is ok'.format(iteration+1,lc))
            else:
                log.info('Iteration {0} Expected: Fabric card {1} is ok Actual: Fabric card {2} not ok'.format(iteration+1,lc))
                result=False
        if not len(showlcdict.keys()):
            log.info('Expected: atleast one Fabric card to be ok Actual: No fabric card found')
            result=False
        if result or iteration == cmdnamespace.iterations-1:
           break
        else:  
           log.info("Wait for {0} second for next iteration".format(cmdnamespace.interval))
           time.sleep(cmdnamespace.interval)
      if result:
           testResult('pass','Fabric card status for {0} Fabric cards is ok'.format(showlcdict.keys()),log)
      else:
           testResult('fail','Some or all of the Fabric cards is not ok',log)





class verifyRunningStartupConfigAreSame():
  "  verifyRunningStartupConfigAreSame - Method to verify the Running and startup config are same\
  \
  mandatory args: hdl, log\
  \
  Usage Examples: verifyRunningStartupConfigAreSame(hdl, log)"
  def __init__(self,hdl, log):
    self.result='pass'
    #Get running and startup configs using get methods
    runcfg=getRunningConfig(hdl, log)
    stcfg=getStartupConfig(hdl, log)

    #Compare running and startup configs 
    if runcfg==stcfg:
        testResult('pass','Running and Startup configs are same', log)
    else:
        testResult('fail','Running and Startup configs are different', log)




class verifySupIsInHaStandbyMode():
  "  verifySupIsInHaStandbyMode - Method to verify HA standby State\
  \
  mandatory args: hdl, log\
  \
  Usage Examples: verifySupIsInHaStandbyMode(hdl, log)"
  def __init__(self,hdl, log):
    self.result='pass'
    # Check HA operational mode from - show redundancy status
    ha_mode=getHAOperationalMode(hdl, log)
    if ha_mode != 'HA':
        testResult('fail','HA operational mode is {0}, expected HA'.format(ha_mode), log)
    else:        
        # If HA operational mode is 'HA', then verify HA standby state
        # on each active VDC on the Dut
        vdc_dict=getVdcHaStandbyStateDict(hdl, log)
        if len(vdc_dict.keys())==0:
            testResult('pass','HA opermode is HA and no vdcs on Dut', log)
        for vdcid in vdc_dict.keys():   
            if vdc_dict[vdcid]['Other_supervisor']=='HA standby':
                testResult('pass','vdc {0} is in HA standby mode'.format(vdcid), log)
            else:
                testResult('fail','vdc {0} is in {1} mode -expected HA standby'.format(vdcid, \
                                   vdc_dict[vdcid]['Other_supervisor']), log)




class verifyNoInterfaceErrInactive():
  "  verifyNoInterfaceErrInactive - Method to verify that all interfaces are in active state\
  \
  mandatory args: hdl, log\
  \
  Optional args: interface or list of interfaces\
  Usage Examples: verifyNoInterfaceErrInactive(hdl, log) - Verifies all interfaces not in Err-disabled,Err-vlans,inactive\
  verifyNoInterfaceErrInactive(hdl, log, '-err-disabled') - Verifies all interfaces not in Err-disabled\
  verifyNoInterfaceErrInactive(hdl, log, '-interface eth1/9,1/10') - Verifies 1/9-10 is not in Err-disabled,Err-vlans,inactive\
  verifyNoInterfaceErrInactive(hdl, log, '-interface eth1/9,1/10 -err-disabled') - Verifies eth1/9-10 is not Err disabled"
  def __init__(self,hdl, log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['interfaces']='-type str'
    arggrammar['err-disabled']='-type bool'
    arggrammar['err-vlans']='-type bool'
    arggrammar['inactive']='-type bool'
    cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    errdisableddict=getInterfaceStatusDict(hdl, log, '-err-disabled')
    errvlansdict=getInterfaceStatusDict(hdl, log, '-err-vlans')
    inactivedict=getInterfaceStatusDict(hdl, log, '-inactive')
    result=True
    if not len(cmdnamespace.KEYS) or (len(cmdnamespace.KEYS) == 1 and cmdnamespace.interfaces):
        cmdnamespace.KEYS=['err-disabled','err-vlans','inactive'] 

    if cmdnamespace.interfaces:
        for interface in strtolist(cmdnamespace.interfaces):
            if (str(interface) in errdisableddict.keys()) and 'err-disabled' in cmdnamespace.KEYS:
                testResult('fail','Expected: {0} not to be in err-disabled state Actual: {0} found in err-disabled interface list'.format(interface),log)
                result=False
            if (str(interface) in errvlansdict.keys()) and 'err-vlans' in cmdnamespace.KEYS:
                testResult('fail','Expected: {0} not to be in err-vlans state Actual: {0} found in err-vlans interface list'.format(interface),log)
                result=False
            if (str(interface) in inactivedict.keys()) and 'inactive' in cmdnamespace.KEYS:
                testResult('fail','Expected: {0} not to be in inactive state Actual: {0} found in inactive interface list'.format(interface),log)
                result=False
        if result:
                cmdnamespace.KEYS.pop(cmdnamespace.KEYS.index('interfaces'))
                testResult('pass','{0} is not in {1} states'.format(cmdnamespace.interfaces,cmdnamespace.KEYS),log)
    else:
        if len(errdisableddict.keys()) and 'err-disabled' in cmdnamespace.KEYS:
            testResult('fail','Expected: No err-disabled interfaces: Actual: Found {0} interfaces in err-disabled state'.format(errdisableddict.keys()),log)
            result=False
        if len(errvlansdict.keys()) and 'err-vlans' in cmdnamespace.KEYS:
            testResult('fail','Expected: No err-vlans interfaces: Actual: Found {0} interfaces in err-vlans state'.format(errvlansdict.keys()),log)
            result=False
        if len(inactivedict.keys()) and 'inative' in cmdnamespace.KEYS:
            testResult('fail','Expected: No inactive interfaces: Actual: Found {0} interfaces in inactive state'.format(inactivedict.keys()),log)
            result=False
        if result:
            testResult('Pass','No interfaces found in {0} states'.format(cmdnamespace.KEYS),log)




class verifyIpv4SVIs():
  "  verifyIpv4SVIs - Method to verify the state of SVIs\
  \
  mandatory args: hdl, log\
  \
  Optional args: SVI or list of SVI, SVI dict (Dict's format is same as getIpv4InterfaceBriefDict)\
  Usage Examples: verifyIPv4SVIs(hdl, log) - Verifies all SVIs in default VRF is active\
  verifyIPv4SVIs(hdl, log, '-vrf test') - Verifies all SVIs in test VRF is active\
  verifyIPv4SVIs(hdl, log, **svidict) - Verifies against svidict\
  verifyIPv4SVIs(hdl, log, '-svis Vlan1,Vlan3,Vlan4') - Verifies given 3 SVIs are up"
  def __init__(self,hdl, log, *args, **svidict):
    self.result='pass'
    arggrammar={}
    arggrammar['svis']='-type str'
    arggrammar['vrf']='-type str'
    cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if cmdnamespace.vrf:
        ipv4dict=getIpv4InterfaceBriefDict(hdl, log, '-vrf '+cmdnamespace.vrf)
    else:
        ipv4dict=getIpv4InterfaceBriefDict(hdl, log)
    result=True
    if cmdnamespace.svis:
        for svi in strtolist(cmdnamespace.svis):
            if svi not in ipv4dict.keys(): 
                testResult('fail','Expected: Some info for SVI:{0} Actual: No Info for SVI:{0}'.format(svi),log)
                result=False
            elif 'Interface Status' not in ipv4dict[svi].keys():
                testResult('fail','Expected: Some info for SVI:{0} Actual: No Info for SVI:{0}'.format(svi),log)
                result=False
            elif ipv4dict[svi]['Interface Status'] == 'protocol-up/link-up/admin-up': 
                log.info('SVI {0} Status is up'.format(svi))
            else:
                testResult('fail','Expected: SVI {0} Status protocol-up/link-up/admin-up Actual: Status is {1}'.format(svi,ipv4dict[svi]['Interface Status']),log)
                result=False
        if result:
            testResult('pass','SVI {0} Status is up'.format(svi),log)
    if svidict:
        # The values from this dictionary will be verified against the values from get proc
        # Check Expected keys are in output keys , return fail if it's not,
        for svi in svidict.keys():
            if svi not in ipv4dict.keys(): 
                testResult('fail','Expected: SVI:{0} to be available in show output Actual: No Info for SVI:{0}'.format(svi),log)
                result=False
                continue

            for key in svidict[svi].keys():
                if key not in ipv4dict[svi].keys(): 
                    testResult('fail','Expected: SVI:{0} key:{1} to have some value Actual : No Info'.format(svi,key),log)
                    result=False
                    continue
                if str(svidict[svi][key])==ipv4dict[svi][key]:
                    log.info('SVI {0} {1} is {2}'.format(svi, key, ipv4dict[svi][key]))
                else:
                    testResult('fail','SVI {0} {1} expected:{2} actual:{3}'.format(svi, key, svidict[svi][key], ipv4dict[svi][key]),log)
                    result=False
        if result:
            testResult('pass','Given svidict {0} passed'.format(svidict),log)

    if (not cmdnamespace.svis) and (not svidict):
        # Verify all SVIs are okay
        for svi in ipv4dict.keys():
            if not svi.startswith('Vlan'):
                continue
            if re.search( 'down', ipv4dict[str(svi)]['Interface Status'], re.I ):
                testResult('fail','FAIL SVI {0} Expected: protocol-up/link-up/admin-up Actual: {1}'.format(svi,ipv4dict[str(svi)]['Interface Status']),log)
                result=False           
            else:
                log.info('SVI {0} Status is up'.format(svi))
        if not len(ipv4dict.keys()):
            testResult('fail','Expected: atleast one SVI expeted Actual: SVI found',log)
            result=False
        if result:
            testResult('pass','All interfaces are up',log)




class verifyIpv6SVIs():
  "  verifyIpv6SVIs - Method to verify the state of SVIs\
  \
  mandatory args: hdl, log\
  \
  Optional args: SVI or list of SVI, SVI dict (Dict's format is same as getIpv4InterfaceBriefDict)\
  Usage Examples: verifyIPv6SVIs(hdl, log) - Verifies all SVIs in default VRF is active\
  verifyIPv6SVIs(hdl, log, '-vrf test') - Verifies all SVIs in test VRF is active\
  verifyIPv6SVIs(hdl, log, **svidict) - Verifies against svidict\
  verifyIPv6SVIs(hdl, log, '-svis Vlan1,Vlan3,Vlan4') - Verifies given 3 SVIs are up"
  def __init__(self,hdl, log, *args, **svidict):
    self.result='pass'
    arggrammar={}
    arggrammar['svis']='-type str'
    arggrammar['vrf']='-type str'
    cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if cmdnamespace.vrf:
        ipv6dict=getIpv6InterfaceBriefDict(hdl, log, '-vrf '+cmdnamespace.vrf)
    else:
        ipv6dict=getIpv6InterfaceBriefDict(hdl, log)
    result=True

    if cmdnamespace.svis:
        for svi in strtolist(cmdnamespace.svis):
            if svi not in ipv6dict.keys(): 
                testResult('fail','Expected: Some info for SVI:{0} Actual: No Info for SVI:{0}'.format(svi),log)
                result=False
            elif ipv6dict[svi]['Interface Status'] == 'protocol-up/link-up/admin-up': 
                log.info('SVI {0} Status is up'.format(svi))
            else:
                testResult('fail','Expected: SVI {0} Status protocol-up/link-up/admin-up Actual: Status is {1}'.format(svi,ipv6dict[svi]['Interface status']),log)
                result=False
        if result:
            testResult('pass','SVI {0} Status is up'.format(svi),log)
    if svidict:
        # The values from this dictionary will be verified against the values from get proc
        # Check Expected keys are in output keys , return fail if it's not,
        for svi in svidict.keys():
            if svi not in ipv6dict.keys(): 
                testResult('fail','Expected: SVI:{0} to be available in show output Actual: No Info for SVI:{0}'.format(svi),log)
                result=False
                continue

            for key in svidict[svi].keys():
                if key not in ipv6dict[svi].keys(): 
                    testResult('fail','Expected: SVI:{0} key:{1} to have some value Actual : No Info'.format(svi,key),log)
                    result=False
                    continue
                if str(svidict[svi][key])==ipv6dict[svi][key]:
                    log.info('SVI {0} {1} is {2}'.format(svi, key, ipv6dict[svi][key]))
                else:
                    testResult('fail','SVI {0} {1} expected:{2} actual:{3}'.format(svi, key, svidict[svi][key], ipv6dict[svi][key]),log)
                    result=False
        if result:
            testResult('pass','Given svidict {0} passed'.format(svidict),log)

    if (not cmdnamespace.svis) and (not svidict):
        # Verify all SVIs are okay
        for svi in ipv6dict.keys():
            if not svi.startswith('Vlan'):
                continue
            if re.search( 'down', ipv6dict[str(svi)]['Interface Status'], re.I ):
                testResult('fail','FAIL - SVI {0} Expected: protocol-up/link-up/admin-up Actual: {1}'.format(svi,ipv6dict[str(svi)]['Interface Status']),log)
                result=False           
            else:
                log.info('SVI {0} Status is up'.format(svi))
        if not len(ipv6dict.keys()):
            testResult('fail','Expected: atleast one SVI expeted Actual: SVI found',log)
            result=False
        if result:
            testResult('pass','All interfaces are up',log)


class verifyModules(object):
    '''Verify that all non-FEX modules are up.
  
    Usage Examples: 
     verifyModules(hdl, log) # Verify all modules are up
     verifyModules(hdl,log,'-modules 101') # Verify all given Modules are up
     verifyModules(hdl,log,'-modules 101,102 -state online') # Verify given modules are in given state
     verifyModules(hdl,log,'-model N7K-F248XP-25') # Verify modules of given model are up
     verifyModules(hdl,log,'-model N7K-F248XP-25 -state online') \
         # Verify given model modules are in given state
     verifyModules(hdl,log,'-model N7K-F248XP-25 -modules 101 -state online') \
         # Verify given model, given modules are in given state'''

    def __init__(self,hdl, log, *args):
        self.result='pass'
        arggrammar={}
        arggrammar['model']='-type str -default all'
        arggrammar['modules']='-type str -format [0-9, ]+|all -default all'
        arggrammar['state']='-type str -choices ["online","ok","powered-dn","powered-up","testing",\
            "initializing","pwr-cycld","active","ha-standby","failure","inserted","all"] -default ok'
        arggrammar['iteration']='-type int -default 1'
        arggrammar['interval']='-type int -default 30'

        cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

        modules=cmdnamespace.modules
        state=cmdnamespace.state
        model=cmdnamespace.model

        if modules=='all':
            modules=getModuleList(hdl,log,'-state all -model {0}'.format(model))

        for iteration in range(cmdnamespace.iteration):
            result=True
            if cmdnamespace.iteration>1:
                 log.info ('Starting iteration {0} of {1}'.format(iteration,cmdnamespace.iteration))

            module_list=getModuleList(hdl,log,'-state {0} -model {1}'.format(state,model))
            if compareVars(modules,module_list,log) == 'pass':
                testResult('pass','Modules found in expected state',log)
                return
            else:
                log.info('Modules are not in expected state')
                result=False

            if iteration < cmdnamespace.iteration-1:
                log.info('Waiting for {0} seconds before next iteration'.format(cmdnamespace.interval))
                time.sleep(cmdnamespace.interval)

        if not result:
            hdl.iexec('delete bootflash:/sh_tech_mod_all no-prompt')
            hdl.iexec('show tech-support module all > bootflash:/sh_tech_mod_all',timeout=180)
            testResult('fail','For given modules: \"{0}\", model: \"{1}\", state: \"{2}\" '\
                .format(cmdnamespace.modules,cmdnamespace.model,cmdnamespace.state) + \
                'not all modules are in expected state',log)


class verifyFexModules():
  "  verifyFexModules - Method to verify that all Fex modules are up\
  \
  mandatory args: hdl, log\
  \
  Optional args: module or list of modules\
  Usage Examples: verifyFexModules(hdl, log) - Verifies all Fex Modules are up\
  verifyFexModules(hdl, log, '-modules <modules>') - Verifies all given Fex Modules are up\
  verifyFexModules(hdl, log, '-modules <modules> -state <state>') - Verifies given Fex modules are in given state\
  verifyFexModules(hdl, log, '-model <model>') - Verifies given Fex model modules are in given state\
  verifyFexModules(hdl, log, '-model <model> -state <state>') - Verifies given Fex model modules are in given state\
  verifyFexModules(hdl, log, '-model <model> -modules <modules> -state <state>') - Verifies given Fex model, given modules are in given state"
  def __init__(self,hdl, log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['model']='-type str'
    arggrammar['state']='-type str'
    arggrammar['modules']='-type str'
    arggrammar['iteration']='-type int -default 1'
    arggrammar['interval']='-type int -default 30'
    cmdnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    argstr=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'str',['modules','iteration','interval','state'],'-')

    if not cmdnamespace.state:
        state='Online'
    else:
        state=cmdnamespace.state

    # Ensure the FEX is anything but Online
    if state=='not_online':
        argstr+=' -state Online'
    else:
        argstr+=' -state {0}'.format(state)

    if cmdnamespace.modules:
      for iteration in range(cmdnamespace.iteration):
        result=True
        fexlist = getFexModuleList(hdl,log,argstr)
        for module in strtolist(cmdnamespace.modules):
            if state=='not_online':
                if module in fexlist:
                    log.info('Iteration {1} Expected: Module {0} to be not online. Actual: {0} is Online'.format(module,iteration+1))
                    result=False
                else :
                    log.info('Module {0} found'.format(module))
            else:
                if not module in fexlist:
                    log.info('Iteration {2} Expected: Module {0} to be {1} Actual: {0} not in {1} state or not found'.format(module,state,iteration+1))
                    result=False
                else :
                    log.info('Module {0} found'.format(module))

        if result or iteration == cmdnamespace.iteration-1:
            break
        else:
            log.info("Sleeping for {0} second".format(cmdnamespace.interval))
            time.sleep(cmdnamespace.interval)
      if result:
            testResult('pass','Fex modules {0} found'.format(cmdnamespace.modules),log)
      else:
            testResult('fail','Fex modules {0} not found'.format(cmdnamespace.modules),log)
    else:
      for iteration in range(cmdnamespace.iteration):
        allfexlist = getFexModuleList(hdl,log,'-state any')
        fexlist = getFexModuleList(hdl,log,argstr)
        result=True
        fexlist.sort()
        allfexlist.sort()
        if state=='not_online':
            if not fexlist:
                testResult('pass','For given args {0} no online modules found'.format(cmdnamespace),log)
                return
            else:
                log.info("Sleeping for {0} second".format(cmdnamespace.interval))
                time.sleep(cmdnamespace.interval)
                result=False
        else:
            if fexlist==allfexlist:
                testResult('pass','For given args {0} modules {1} found'.format(cmdnamespace,fexlist),log)
                return
            else:
                log.info("Sleeping for {0} second".format(cmdnamespace.interval))
                time.sleep(cmdnamespace.interval)
                result=False

      if not result:
            testResult('fail','For given args {0} No modules found'.format(cmdnamespace),log)



class verifySysmgrState():
  "  verifySysmgrState - Method to verify the sysmgr state\
  \
  mandatory args: hdl, log\
  \
  Optional args: , sysmgr state dict (Dict's format is same as getIpv4InterfaceBriefDict)\
  Usage Examples: verifySysmgrState(hdl, log) - Verifies both active and standby\
  super-state in SYSMGR_SUPERSTATE_STABLE\
  verifySysmgrState(hdl, log, '-state 'SRV_STATE_MASTER_ACTIVE_ALONE')\
  - Verifies the current sysmgr state is\
  SRV_STATE_MASTER_ACTIVE_ALONE\
  verifySysmgrState(hdl, log, **dict) - Verifies sysmgr state against dict\
  verifySysmgrState(hdl, log, '-vdc vdc3', **dict) - Verifies sysmgr\
  state against dict in VDC3"
  def __init__(self,hdl, log, *args, **dict):
    self.result='pass'
    arggrammar={}
    arggrammar['vdc']='-type str'
    arggrammar['state']='-type str'
    arggrammar['local_state']='-type str'
    arggrammar['standby_state']='-type str'
    arggrammar['switchover_count']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if ns.vdc:
        vdc=ns.vdc
    else:
        vdc='default'
    
    outputDict=getSysmgrState(hdl, log, '-vdc {0}'.format(vdc))
    if not outputDict:
        testResult('fail','No sysmgr state output available',log)
        return None

    result=True
    arg_cnt=0
    if (ns.state and ns.state!=outputDict['State']):
        testResult('fail','Sysmgr state - Expected:{0} Actual:{1}'.format(ns.state,outputDict['State']),log)
        result=False
    elif (ns.state): 
        log.info('Sysmgr state is the same as expected in:{0}'.format(ns.state))
        arg_cnt+=1
 
    if  (ns.local_state and ns.local_state!=outputDict['Local_State']):
        testResult('fail','Sysmgr local super-state - Expected:{0} Actual:{1}'.format(ns.local_state,outputDict['Local_State']),log)
        result=False
    elif (ns.local_state):
        log.info('Sysmgr local-super state is the same as expected in:{0}'.format(ns.local_state))
        arg_cnt+=1
   
    if (ns.standby_state and ns.standby_state!=outputDict['Standby_State']):
        testResult('fail','Sysmgr standby super-state - Expected:{0} Actual:{1}'.format(ns.standby_state,outputDict['Standby_State']),log)
        result=False
    elif (ns.standby_state): 
        log.info('Sysmgr standby-super state is the same as expected in:{0}'.format(ns.standby_state))
        arg_cnt+=1


    if (ns.switchover_count and ns.switchover_count!=outputDict['Switchover_Count']):
        testResult('fail','Sysmgr switchover count - Expected:{0} Actual:{1}'.format(ns.switchover_count,outputDict['Switchover_Count']),log)
        result=False
    elif (ns.switchover_count): 
        log.info('Sysmgr switchover_count is the same as expected in:{0}'.format(ns.switchover_count))
        arg_cnt+=1

    if (result and arg_cnt):
        testResult('pass','Sysmgr state is the same as expected in args:{0}'.format(args),log)
 
    if dict:
        result=True
        # The values from this dictionary will be verified against the values from get proc
        # Check Expected keys are in output keys , return fail if it's not,
        for key in dict.keys():
            if key not in outputDict.keys(): 
                testResult('fail','Info of {0} is not available in sysmgr state output'.format(key),log)
                result=False
                continue
            if dict[key].lower()!=outputDict[key].lower():
                testResult('fail','Sysmgr state info of {0} is expected:{1} actual:{2}'.format(key, dict[key], outputDict[key]),log)
                result=False
            else:
                log.info('Sysmgr state of {0} is the same as expected in:{1}'.format(key,dict[key]))
        if result:
            testResult('pass','Given sysmgr state dict {0} passed'.format(dict),log)

    if (len(ns.KEYS)==0 or (len(ns.KEYS)==1 and 'vdc' in ns.KEYS)) and (not dict):
        # Verify both local super_state and standby super_state in SYSMGR_SUPERSTATE_STABLE
        if (outputDict['Local_State']=='SYSMGR_SUPERSTATE_STABLE' and outputDict['Standby_State']=='SYSMGR_SUPERSTATE_STABLE'):
            testResult('pass','Both sysmgr local and standby super-state are in SYSMGR_SUPERSTATE_STABLE',log)
        else:
            testResult('fail','Sysmgr local super-state or standby super-state are not in SYSMGR_SUPERSTATE_STABLE',log)
 






class verifyVpcs():
  ''' verifyVpcs - Method to verify vPCs\
  \
  Mandatory args\
  \
  hdl - switch handle object from icon\
  log - harness/python logging object\
  \
  Optional args\
  \
  vpc_list - Comma separated list of virtual Port-channels\
  vpc_dict - Dictionary with vPC as key and 'Status' as the value\
  \
  Sample Usage:\
  verifyVpcs( hdl, log )\
  verifyVpcs(hdl, log, '-vpc_list 1,2,3')\
  
      
    in_dict={}
    in_dict['1']={}
    in_dict['2']={}
    in_dict['1']['Status']='up'
    in_dict['2']['Status']='up'
    
    verifyVpcs(hdl, log, **in_dict)
    verifyVpcs( hdl, log, vpc_dict=<dict> )\
  '''
  def __init__(self, hdl, log, *args, **vpc_dict ):
     self.result='pass'

     arggrammar={}
     arggrammar['vpc_list']='-type str'
     arggrammar['status']='-type str -default up'
     parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

     # Get list of vPCs configured on the switch
     vpc_out_list=getVpcList(hdl,log)
     vpc_get_dict=getVpcDict(hdl, log)
     # If vpc_list is given use it, otherwise get all port-channels configured
     if parse_output.vpc_list:
        vpc_list=parse_output.vpc_list.split(',')
     else:
        vpc_list=getVpcList(hdl,log)

     vpc_status=parse_output.status

     # Get Status of all Interfaces for VPC status verification ..
     intf_dict=getInterfaceBriefDict( hdl, log )

     # If pc dict is given then ..
     if vpc_dict:
        # Verify the status of each port-channels
        for vpc_nam in vpc_dict.keys():
            if vpc_nam not in vpc_out_list:
                testResult('fail','The vPC given in the vpc_dict {0} does not exist on the switch'.format( vpc_nam), log)
                continue
            else:
                vpc_po=vpc_get_dict[vpc_nam]['Port']
                if not re.search( vpc_dict[vpc_nam]['Status'], intf_dict[vpc_po]['Status'], flags=re.I ):
                    testResult('fail', 'vPC Status not matching for vPC {0}, Expected Status {1}, Actual status on the switch {2}'.format( vpc_nam, vpc_dict[vpc_nam]['Status'], intf_dict[vpc_po]['Status']), log )
                else:
                    log.info('vPC {0} is in correct state {1}'.format(vpc_nam, vpc_dict[vpc_nam]['Status']))
     else:
        # If dictionary not given ..
        for vpc_id in vpc_list:
            vpc_nam=vpc_get_dict[vpc_id]['Port']
            if not re.search( vpc_status, intf_dict[vpc_nam]['Status'], re.I ):
                testResult('fail', 'vPC {0} - Expected Status {1}, Actual status on the switch {2}'.format( vpc_nam, vpc_status, intf_dict[vpc_nam]['Status']), log )
            else:
                log.info('vPC {0} is in correct state - {1}'.format(vpc_nam, vpc_status))
                



class verifyVpcMembers():
  "  verifyVpcMembers - Method to verify vPC portChannelMembers\
  \
  Mandatory args\
  \
  hdl - switch handle object from icon\
  log - harness/python logging object\
  \
  Optional args\
  \
  vpc_list - Comma separated list of vPC Port-channels\
  vpc_dict - Dictionary with vPC  as key and 'Status' as the value\
  \
  Sample Usage:\
  verifyVpcMembers( hdl, log)\
  verifyVpcMembers( hdl, log, '-vpc_list=1,2' )\
  verifyVpcMembers( hdl, log, '-vpc_list=1,2 -status down' )\
  verifyVpcMembers( hdl, log, vpc_memb_dict )\
  \
  vpc_memb_dict={}\
  vpc_memb_dict['1']['Eth3/14']={}\
  vpc_memb_dict['1']['Eth3/14']['Status']='up'\
  "
  def __init__(self, hdl, log, *args, **vpc_memb_dict ):
     self.result='pass'


     arggrammar={}
     arggrammar['vpc_list']='-type str'
     arggrammar['status']='-type str -default up'
     parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

     # Get list of vPCs configured on the switch
     vpc_out_list=getVpcList(hdl,log)

     # If pc_list is given use it, otherwise get all port-channels configured
     if parse_output.vpc_list:
        vpc_list=strtolist(parse_output.vpc_list)
     else:
        vpc_list=getVpcList(hdl,log)
     
     vpc_status=parse_output.status

     # Get Status of all Interfaces for vPC member status verification ..
     intf_dict=getInterfaceBriefDict( hdl, log )

     # If vpc dict is given then ..
     if vpc_memb_dict:
        # Verify the status of each port-channels

        for vpc_nam in vpc_memb_dict.keys():
            if vpc_nam not in vpc_out_list:
                testResult('fail','The vPC given in the vpc_dict {0} does not exist on the switch'.format( vpc_nam), log )
                continue
            else:
                vpc_out_dict=utils.getVpcDict( hdl, log, '-vpc {0}'.format(vpc_nam) )
                pc_nam=vpc_out_dict[vpc_nam]['Port']
                vpc_memb_list=utils.getPortChannelMemberList( hdl, log, '-pc_nam {0}'.format(pc_nam) )
                for vpc_membt in vpc_memb_list:
                    vpc_memb=normalizeInterfaceName( log, vpc_membt )
                    if not re.search( vpc_memb_dict[vpc_nam][vpc_memb]['Status'],                                          \
                        intf_dict[vpc_memb]['Status'], flags=re.I ):
                        testResult('fail', 'vPC Member Status not matching for VPC {0} Member {1},                         \
                           Expected Status {1}, Actual status on the switch {2}'.format( vpc_nam, vpc_memb,                \
                           vpc_memb_dict[vpc_nam][vpc_memb]['Status'],                                                     \
                           intf_dict[vpc_memb]['Status']), log )
                    else:
                        log.info('vPC {0} member {1} is in expected state {2}'.format(vpc_nam,                             \
                           vpc_memb, vpc_memb_dict[vpc_nam][vpc_memb]['Status'] )) 
     # If dictionary not given ..
     else:
        for vpc_nam in vpc_list:
            vpc_out_dict=utils.getVpcDict( hdl, log, '-vpc {0}'.format(vpc_nam) )
            pc_nam=vpc_out_dict[vpc_nam]['Port']
            vpc_memb_list=getPortChannelMemberList( hdl, log, '-pc_nam {0}'.format(pc_nam) )
            for vpc_memb in vpc_memb_list:
                if not re.search( vpc_status, intf_dict[normalizeInterfaceName( log, vpc_memb )]['Status'], re.I ):
                    testResult('fail', 'vPC member {0} - Expected Status {1}, Actual Status {2} on {3}'\
                                   .format(vpc_nam,vpc_status,intf_dict[normalizeInterfaceName(log,vpc_memb)]['Status'],\
                                               hdl.switchName),log)
                else:
                    log.info('vPC Member {0} is in correct state - {1}'.format(vpc_nam, vpc_status))





class verifyVpcConsistencyParameters():
  "  verifyVpcConsistencyParameters - Method to verify vPC Consistency Parameters\
  \
  Mandatory args\
  \
  hdl - switch handle object from icon\
  log - harness/python logging object\
  \
  Optional args\
  \
  -flag - valid choices are vlans, global, interface, vpc. Defaults to global if not given\
  -interface - Port-channel name for which vPC consistency check needs to be done\
  -vpc - Vpc ID for which consistency check has to be done\
  \
  Sample Usage:\
  verifyVpcConsistencyParameters( hdl, log, '-flag global')\
  verifyVpcConsistencyParameters( hdl, log, '-flag vlans')\
  verifyVpcConsistencyParameters( hdl, log, '-flag interface -interface Po1')\
  verifyVpcConsistencyParameters( hdl, log, '-flag vpc -vpc 1')\
  "
  def __init__(self, hdl, log, *args ):
     self.result='pass'

     arggrammar={}
     arggrammar['flag']='-type str -choices ["vlans","global","interface","vpc"] -default global'
     arggrammar['interface']='-type str'
     arggrammar['vpc']='-type int'

     # parse the arguments ..
     ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

     # call getVpcConsistencyParametersDict with Appropriate arguments ..
     if ns.flag=='global':
         vpc_consist_dict=getVpcConsistencyParametersDict( hdl, log, '-flag global' )
     elif ns.flag=='vlans':
         vpc_consist_dict=getVpcConsistencyParametersDict( hdl, log, '-flag vlans' )
     elif ns.flag=='interface':
         vpc_consist_dict=getVpcConsistencyParametersDict( hdl, log, '-interface {0}'.format(ns.interface) )
     elif ns.flag=='vpc':
         vpc_consist_dict=getVpcConsistencyParametersDict( hdl, log, '-vpc {0}'.format(ns.vpc) )
     else:
         testResult( 'fail', 'Invalid argument passed to verifyVpcConsistencyParameters, please check', log )
         return

     log.info('Validating vPC consistency parameters for {0}'.format(ns.flag))
     if not vpc_consist_dict:
         testResult( 'fail', 'No info exist for vPC consistency parameters', log )
         self.result = 'fail'
         return

     log.debug('Value of vpc_consist_dict - {0}'.format(vpc_consist_dict))
     # Continue with verifications ...
     for vpc_key in vpc_consist_dict.keys():
          if ns.flag=='vlans':
              if not re.search( 'success', vpc_consist_dict[vpc_key]['Reason_Code'], re.I ):
                 testResult('fail', 'FAIL - vPC conistency check for vlans not having success for {0}'.format( vpc_key ),  \
                    log )
          else:
              if str(vpc_consist_dict[vpc_key]['Local_Value'])!=str(vpc_consist_dict[vpc_key]['Peer_Value']):
                 testResult( 'fail', 'FAIL - vPC consistency parameters not matching for flag {0} for {1}, Local Value -,  \
                    {2} Peer Value - {3}'.format( ns.flag, vpc_key, vpc_consist_dict[vpc_key]['Local_Value'],              \
                 vpc_consist_dict[vpc_key]['Peer_Value'] ), log )






class verifySysmgrServiceState():
  "  verifySysmgrServiceState - Method to verify the sysmgr service state\
  \
  mandatory args: hdl, log\
  \
  Optional args: , sysmgr service state dict - {'pixm': {'Restart_Count': '1', 'SAP': '176', 'PID': '4309', 'UUID': '0x133', 'Service_State': 'SRV_STATE_HANDSHAKED'}}\
  Usage Examples: verifySysmgrServiceState(hdl, log,'-services pixm ospf') - Verifies both services\
  in SRV_STATE_HANDSHAKED\
  SRV_STATE_MASTER_ACTIVE_ALONE\
  verifySysmgrServiceState(hdl, log, **dict) - Verifies sysmgr service state against dict state"
  def __init__(self,hdl, log, *args, **dict):
    self.result='pass'
    arggrammar={}
    arggrammar['services']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if (not ns.services and not dict):
        testResult('fail','Either services list or services dict should be specified', log)
        return None
    
    if ns.services:
        outputDict=getSysmgrServiceStateDict(hdl, log, '-services {0}'.format(ns.services))
        if not outputDict:
            testResult('fail','No sysmgr service state available in the output',log)
            return None
        else:
            result=True
            for key in outputDict.keys():
                if outputDict[key]['Service_State']!='SRV_STATE_HANDSHAKED':
                    testResult('fail','Sysmgr service {0} is not expected. actual: {1} expect:SRV_STATE_HANDSHAKED'.format(key,outputDict[key]['Service_State']),log)
                    result=False
            if result:
                testResult('pass','Sysmgr services of {0} are in the expected state of SRV_STATE_HANDSHAKED'.format(ns.services),log)

    if dict:
        services=' '.join(dict.keys())
        outputDict=getSysmgrServiceStateDict(hdl, log, '-services {0}'.format(services))
        if findDict(log,dict,outputDict,2):
            testResult('pass','Sysmgr services of {0} are in the expected state as {1}'.format(dict,outputDict),log)
        else:
            testResult('fail','Sysmgr services of {0} are not in the expected state as {1}'.format(dict,outputDict),log)            
        return None




class verifyInterfaceErrorCounter():
  "  verifyInterfaceErrorcounter - Method to verify the interface error counter, all error\
  counter should be zero unless threshold is specified.\
  When threshold specificed in dict, the corresponding conter\
  can be non-zero but below the threshold, the other counters\
  should be all zero.\
  mandatory args: hdl, log     \
  e.g. dict={'Eth3/1':{'FCS-Err':'10','Carri-Sen':'10'}, 'Eth3/4':{'Runts':'10','Giants':'15'}}\
  \
  Optional args: interfaces, dict\
  Usage Examples: verifyInterfaceErrorcounter(hdl, log,'-interfaces eth3/1, eth3/4') - Verifies\
  all error counter on interfaces are zero\
  verifyInterfaceErrorcounter(hdl, log,**dict) - Verify all error counter are\
  below the threshold as in dict"
  def __init__(self,hdl, log, *args, **dict):
    self.result='pass'
    arggrammar={}
    arggrammar['interfaces']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if (not ns.interfaces and not dict):
        result=True
        int_list=getInterfaceList(hdl,log,'-physical') 
        out_dict=getInterfaceErrorCounter(hdl,log,listtostr(int_list))
        if not out_dict:
            testResult('fail','Interface error counter are not available on {0}'.format(ns.interfaces),log)
            return None
        for key1 in out_dict.keys():
            for key2 in out_dict[key1].keys():
                if (out_dict[key1][key2]!='0' and out_dict[key1][key2]!='--'):
                    testResult('fail','Interface counter of {0} on {1} is non-zero:{2}'.format(key2,key1,out_dict[key1][key2]),log)
                    result=False
        if result:
            testResult('pass','Interface error counter verification passed on {0}'.format(ns.interfaces),log)
    if ns.interfaces:
        result=True
        out_dict=getInterfaceErrorCounter(hdl,log,ns.interfaces)
        if not out_dict:
            testResult('fail','Interface error counter are not available on {0}'.format(ns.interfaces),log)
            return None
        for key1 in out_dict.keys():
            for key2 in out_dict[key1].keys():
                if (out_dict[key1][key2]!='0' and out_dict[key1][key2]!='--'):
                    testResult('fail','Interface counter of {0} on {1} is non-zero:{2}'.format(key2,key1,out_dict[key1][key2]),log)
                    result=False
        if result:
            testResult('pass','Interface error counter verification passed on {0}'.format(ns.interfaces),log)
            
    if dict:
        result=True
        interfaces=' '.join(dict.keys())
        tmp=getInterfaceErrorCounter(hdl,log,interfaces)

        #Normalize the interface name in the key of dictionary
        out_dict=normalizeInterfaceName(log,tmp)
        in_dict=normalizeInterfaceName(log,dict)
        for key1 in in_dict.keys():
            if key1 not in out_dict.keys():
                testResult('fail','Interface {0} error counter is not available'.format(key1),log)
                result=False
            else:            
                for key2 in out_dict[key1]:
                     if (key2 in in_dict[key1] and out_dict[key1][key2]>=in_dict[key1][key2]):
                          testResult('fail','Interface {0} error counter {1} exceeds threshold, actual:{2}, threshold:{3}'.format(key1,key2,out_dict[key1][key2],in_dict[key1][key2]),log)
                          result=False
                     elif (key2 not in in_dict[key1] and out_dict[key1][key2]>'0'):
                          testResult('fail','Interface {0} error counter {1} is non-zero:{2}'.format(key1,key2,out_dict[key1][key2]),log)
                          result=False
                        
        if result:
            testResult('pass','Interface error counter verification passed on {0}'.format(dict.keys()),log)

    return None


###########################################

class verifyMroute ():

  def __init__(self,hdl,log, *args, **mroute_dict):
    self.result='pass'

    # Summary:
    # Source info and Receiver info can be passed as individual value or in form
    # of increment (usefull for 100s of mroutes where many are indentical)
    #  
    # sx_info1 = '11.1.1.1' or sx = '11.1.1.1, 11.1.1.100, 1'
    # the later value will expand to 100 sources while verifying
    # Same goes for rx, increment can be any, all possible values between 
    # start and end are considered for verification
    #
    # rx_info1 = '225.1.1.1'
    # mroute_dict[sx_info1,rx_info1]={}
    # mroute_dict[sx_info1,rx_info1]['rpf_interface']='Ethernet4/1'
    # mroute_dict[sx_info1,rx_info1]['oif_list']=['Ethernet4/1']
    # mroute_dict[sx_info1,rx_info1]['oif_list1']=['Ethernet4/2','Ethernet4/3']
    # mroute_dict[sx_info1,rx_info1]['uptime']='1:1:1'
    # rpf_interface can be a single interface or a list of interfaces (in case of ECMP RPF paths
    # oif_list can be be a list of interfaces or a keyword 'ANY_VALID' which will pass verification 
    # as long as any valid oif interfaces exist.oif_list1 is the oif list with the ECMP paths. 
    # If both oif_list and oif_list1 exist,the actual oif_list should have all interfaces from oif_list
    # plus one interface from oif_list1
    # If only oif_list exists, actual oif_list should be the same as expected oif_list
    # If only oif_list1 exists, actual oif_list should be only one interface from oif_list1
 

    # verifies <show ip mroute> output, accpets values via dict strutcture
    # It does exact match for all parameters passed, rpf_interface can be passed as
    # a list and it passes as long as output has one of this rpf_interface
    # oif_list should always be passed as list (consistence with getMroute)

    # Sample Usage:
    # verifyMroute (hdl,log, value=mroute_dict)
    # verifyMroute (hdl,log,'-vrf default', value=mroute_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_mroute_dict = getMrouteDict(hdl,log,'-vrf ' + parse_output.vrf)
        pass
    else:
        out_mroute_dict = getMrouteDict(hdl,log)
        pass
    if not mroute_dict:
        testResult ('fail','Mroute info not passed for verification',log)
        self.result='fail'
        return None
    else:
        mroute_dict = mroute_dict['value']

    exp_mroute_dict = {}
    # Construct the expected output for verification
    for key in mroute_dict.keys():
        # This can be list
        sources = retIpAddressList(key[0])
        # this can be list
        groups =  retIpAddressList(key[1])
        for source in sources:
            for group in groups:
                exp_mroute_dict[source,group] = {}
                for next_key in mroute_dict[key].keys():
                    if next_key=='oif_list' or next_key=='rpf_interface' or next_key=='oif_list1':
                        exp_mroute_dict[source,group][next_key]=normalizeInterfaceName(log,mroute_dict[key][next_key])
                    else:
                        exp_mroute_dict[source,group][next_key] = mroute_dict[key][next_key]
            pass
        pass

    # Perform Actual verification 
    result=True
    for key in exp_mroute_dict.keys():
        if (key not in out_mroute_dict.keys()):
            testResult ('fail','No info for {0} in mroute output from switch {1}'.format(key,hdl.switchName),log)
            self.result='fail'
            continue
        for next_key in exp_mroute_dict[key].keys():
            if (next_key not in out_mroute_dict[key].keys() and next_key!='oif_list1'):
                testResult ('fail','No info for key:{0} in mroute output for:{1} on {2}'.format(key,next_key,hdl.switchName),log)
                self.result='fail'
                continue
            elif (next_key == 'rpf_interface'):
                if type(exp_mroute_dict[key][next_key])==str and (normalizeInterfaceName(log,out_mroute_dict[key][next_key])!=exp_mroute_dict[key][next_key]):
                    testResult ('fail','RPF interface not in output for {0} on {3}.expected:{1},found:{2}'.\
                                    format(key,exp_mroute_dict[key][next_key],out_mroute_dict[key][next_key],hdl.switchName),log)
                    self.result='fail'
                elif type(exp_mroute_dict[key][next_key])==list and (normalizeInterfaceName(log,out_mroute_dict[key][next_key]) not in exp_mroute_dict[key][next_key]):
                    testResult ('fail','RPF interface not in output for {0} on {3}.expected:{1},found:{2}'.\
                                    format(key,exp_mroute_dict[key][next_key],out_mroute_dict[key][next_key],hdl.switchName),log)
                    self.result='fail'
            elif next_key == 'oif_list': 
                if exp_mroute_dict[key][next_key]=='ANY_VALID':
                    if not len(out_mroute_dict[key][next_key]):
                        testResult ('fail','Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                                        format(key,next_key,exp_mroute_dict[key][next_key],\
                                                   out_mroute_dict[key][next_key],hdl.switchName),log)
                        self.result='fail'
                elif 'oif_list1' not in exp_mroute_dict[key].keys() and (set(exp_mroute_dict[key][next_key]) != set(normalizeInterfaceName(log,out_mroute_dict[key][next_key]))):
                    testResult ('fail','Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                                    format(key,next_key,exp_mroute_dict[key][next_key],\
                                               out_mroute_dict[key][next_key],hdl.switchName),log)
                    self.result='fail'
                elif 'oif_list' in exp_mroute_dict[key].keys() and 'oif_list1' in exp_mroute_dict[key].keys():
                    #With both oif_list and oif_list1 expected, the actual OIFs should be all interfaces in oif_list plus one inerface from oif_list1
                    #verify if expected oif_list is a subset of actual oif_list
                    #and verify there is only one intf from oif_list1 in the actual oif_list
                    if not all(intf in iter(normalizeInterfaceName(log,out_mroute_dict[key]['oif_list'])) for intf in exp_mroute_dict[key]['oif_list']):
                        testResult ('fail','Expected oif_list {1} is not a subset of actual oif_list {0} for {2} on {3}'.
                                   format(out_mroute_dict[key]['oif_list'],exp_mroute_dict[key]['oif_list'],key,hdl.switchName),log)
                        self.result='fail'
                    else:
                        diff= list(set(normalizeInterfaceName(log,out_mroute_dict[key]['oif_list']))-set(exp_mroute_dict[key]['oif_list']))
                        if len(diff)!=1 or diff[0] not in exp_mroute_dict[key]['oif_list1']:
                            testResult('fail','Only one of ECMP paths should be in oif_list for {2} on {3}, expected: one interface from {0}, found:{1}'.format(exp_mroute_dict[key]['oif_list1'],diff,key,hdl.switchName),log)
                            self.result='fail'

            elif next_key=='oif_list1':
                if 'oif_list' not in exp_mroute_dict[key].keys():
                    #with only oif_list1 expected, the actual OIF should be only one intf of the oif_list1
                    if len(out_mroute_dict[key]['oif_list'])!=1 or normalizeInterfaceName(log,out_mroute_dict[key]['oif_list'])[0] not in exp_mroute_dict[key][next_key]:
                        testResult ('fail','Incorrect match for key:{0} for {1} on {4}.expected:only one interface from {2},found:{3}'.\
                                        format(key,next_key,exp_mroute_dict[key][next_key],\
                                                   out_mroute_dict[key]['oif_list'],hdl.switchName),log)
                        self.result='fail'

            elif (exp_mroute_dict[key][next_key] != out_mroute_dict[key][next_key]):
                    testResult ('fail','Incorrect match for key:{0} for {1} on {4}.expected:{2},found:{3}'.\
                                    format(key,next_key,exp_mroute_dict[key][next_key],\
                                               out_mroute_dict[key][next_key],hdl.switchName),log)
                    self.result='fail'

    #if result:
    #   testResult('pass','Mroute verification on ({0}) passes'.format(),log)

    return None

                    
###################################################################################

class verifyPimNeighbor ():

  def __init__(self,hdl, log, *args):
    self.result='pass'
     
    # Verifies neighbors are listed in the PIM neighbor table 

    # Sample Usage:
    # verifyPimNeighbor(hdl,log, '-vrf default -neighbors ' + str(neighbors))
    # verifyPimNeighbor(hdl,log, '-neighbors ' + str(neighbors))

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbors']='-type str -required True'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_pim_dict = getPimNeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_pim_dict = getPimNeighborDict(hdl,log)
    # get list of neighbors which needs to be verified
    neighbors=re.findall('('+rex.IPv4_ADDR+')',parse_output.neighbors)
    # All verification steps as below
    result=True
    for nei in neighbors:
        if (nei not in  out_pim_dict.keys()):
            # If this is not in output then fail cases
            testResult('fail','Neighbor:{0} NOT in PIM neighbor list'.format(nei),log)
            result=False

    if result:
        testResult('pass','PIM neighbor verification passes',log)

 

###############################################################

class verifyPimInterface():

  def __init__(self,hdl, log, *args, **pim_dict):
    self.result='pass'

    # Sample Usage:

    # verifyPimInterface(hdl,log, '-vrf default -interfaces ' + str(interfaces))
    # verifyPimInterface(hdl,log, **pim_dict)

    # pim_dict is build as below
    # pim_dict = {}
    # pim_dict['Ethernet4/1'] = {}
    # pim_dict['Ethernet4/1']['dr'] = '11.1.1.2'
    # pim_dict['Ethernet4/1']['ip'] = '11.1.1.1'
    # pim_dict['Ethernet4/1']['neighbor_count'] = '1'
    # pim_dict['Ethernet4/2'] = {}
    # pim_dict['Ethernet4/2']['dr'] = '12.1.1.2'
    # pim_dict['Ethernet4/2']['ip'] = '12.1.1.1'
    # pim_dict['Ethernet4/2']['neighbor_count'] = '1'
    # pim_dict['loopback0'] = {}
    # pim_dict['loopback0']['dr'] = '1.1.1.1'
    # pim_dict['loopback0']['ip'] = '1.1.1.1'
    # pim_dict['loopback0']['neighbor_count'] = '0'

    # verifyPimInterface(hdl,log,**pim_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['interfaces']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_pim_dict = getPimInterfaceDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_pim_dict = getPimInterfaceDict(hdl,log)
    if parse_output.interfaces:
        interfaces=re.findall('('+rex.INTERFACE_NAME+')',parse_output.interfaces)
    else:
        interfaces = []

    if (not interfaces) and (not pim_dict):
        # No useful info passed for verification, return fail to avoid user errors
        testResult('fail','No useful info passed for verifying PIM interface table',log)
        return None

    # All verification steps as below
    result=True
    if pim_dict:
        # The values from this dictionary will be verified against the values from get proc
        if (compareVars(pim_dict,out_pim_dict,log) != 'pass'):
            testResult('fail','Expected values for PIM interfaces not in PIM interface table',log)
            result=False
    if interfaces:
        # Interfaces will be tested in this section to make sure they are in the list
        for intf in interfaces:
            if (intf not in  out_pim_dict.keys()):
                # If this is not in output then fail cases
                testResult('fail','No info for Interface:{0} in PIM interface table'.format(intf),log)
                result=False

    if result:
        testResult('pass','PIM interface verification passes',log)

    return None

    ################################################################################################



class verifyVpcPeerKeepAlive():
  "  verifyVpcPeerKeepAlive - Method to verify vpc peer keep-alive is up\
  \
  mandatory args: hdl, log"
  def __init__(self,hdl, log):
    self.result='pass'
                  
    # Verify if vpc keep-alive is up
    log.info('Verifying if vPC keepalive is Up')
    show_cmd='show vpc | grep "keep-alive status"'
    output=hdl.iexec(show_cmd)
    patstr="vPC keep-alive status"
    pattern='{0}[ \t]+\:[ \t]+(.+)\r'.format(patstr)
    status_list=re.findall(pattern, output, flags=re.I)
    status=status_list[0].strip(' ')
    if status=='peer is alive':
        testResult('pass','Vpc keep-alive status : {0}'.format(status),log)
    else:
        testResult('fail','Vpc keep-alive status : {0}'.format(status),log)




class verifyVpcPeerLinkStatus():
  "  verifyVpcPeerLinkStatus - Method to verify  Vpc peer-link is up\
  \
  mandatory args: hdl, log"
  def __init__(self,hdl,log):
    self.result='pass'
    #verifies the peer-status in vpc global info
    show_cmd='show vpc | grep "Peer status"'
    output=hdl.iexec(show_cmd)
    patstr="Peer status"
    pattern='{0}[ \t]+\:[ \t]+(.+)\r'.format(patstr)
    status_list=re.findall(pattern, output, flags=re.I)
    peerLinkStatus=status_list[0].strip(' ')
    if peerLinkStatus=='peer adjacency formed ok':
        testResult('pass','Vpc peer status : {0}'.format(peerLinkStatus),log)
        #verifies the peer-link status is up from peerLink Dict
        peerLinkDict=getVpcPeerLinkDict(hdl, log)
        if str(peerLinkDict['Status'])=='up':
            testResult('pass','Vpc peer-link status : {0}'.format(peerLinkDict['Status']),log)
        else:
            testResult('fail','Vpc peer-link status : {0}'.format(peerLinkDict['Status']),log)
    else:
        testResult('fail','Vpc keep-alive status : {0}'.format(peerLinkStatus),log)

##############


class verifyIgmpGroupCount ():

  def __init__(self,hdl, log, *args):
    self.result='pass'
    

    # Sample Usage
    # verifyIgmpGroupCount(hdl,log,'-count 1 -flag sgcount')
    # verifyIgmpGroupCount(hdl,log,'-count 2 -flag stargcount')
    # verifyIgmpGroupCount(hdl,log,'-count 100 -flag total -vrf all')
 
    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['count']='-type str -required True'
    arggrammar['flag']='-type str -choices ["stargcount","sgcount","total"] -default Total'
    arggrammar['verify_iteration']='-type int -default 1'
    arggrammar['interval']='-type int -default 15'

    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    verify_iteration=parse_output.verify_iteration
    interval=parse_output.interval
    count = int(parse_output.count)
    flag = parse_output.flag.lower()
    options = '-flag ' + flag
    if parse_output.vrf:
        options += ' -vrf ' + parse_output.vrf
    if not loop_until("getIgmpGroupCount",(hdl,log,options),count,'-iteration {0} -interval {1}'.format(verify_iteration,interval)):
        testResult('fail','verifyIgmpGroupCount failed on {0}'.format(hdl.switchName),log)
    else:
        testResult('pass','verifyIgmpGroupCount passed on {0}'.format(hdl.switchName),log)


##############

class verifyPimRp ():

  def __init__(self,hdl,log, *args, **rp_dict):
    self.result='pass'
    
    # Sample Usage

    # verifyPimRp(hdl,log,'-vrf vrf1', value=rp_dict)
    # verifyPimRp(hdl,log, value=rp_dict)
 
    arggrammar={}
    arggrammar['vrf']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if not rp_dict:
        testResult ('fail','RP dictionary not passed for verification, return None from method',log)
        return None
    if parse_output.vrf:
        out_rp_dict = getPimRpDict(hdl,log,'-vrf '+ parse_output.vrf)
    else:
        out_rp_dict = getPimRpDict(hdl,log)

    # Verify the output now
    if (compareVars(rp_dict['value'],out_rp_dict,log) != 'pass'):
        testResult ('fail','Expected RP group mapping not present',log)
        return None
    # match found
    testResult ('pass','PIM RP<->group mapping verify passed',log)
    return None
############################


class verifyMrouteCount ():

  def __init__(self,hdl,log, *args):
    self.result='pass'

    # Sample Usage
    # verifyMrouteCount (hdl,log, -count 5')
    # verifyMrouteCount (hdl,log, '-count 10 -flag sgcount -vrf default')
    # verifyMrouteCount (hdl,log, '-count 1 -flag sGCount')
    # Verifies mroute count against the given count

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['count']='-type str -required True'
    arggrammar['flag']='-type str -choices ["sgcount","stargcount","starg-pfxcount","total"] -default total'
    arggrammar['verify_iterations']='-type int -default 1'
    arggrammar['verify_interval']='-type int -default 15'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    count = parse_output.count
    flag = parse_output.flag.lower()
    options = ' '
    verify_iterations=parse_output.verify_iterations
    verify_interval=parse_output.verify_interval

    if parse_output.vrf:
        options += ' -vrf ' + parse_output.vrf 

    verified=False
    for iteration in range(verify_iterations):
        # Get the mroute count
        mroute_dict = getMrouteCountDict(hdl,log,options)
        if (flag == 'total'):
            get_count = mroute_dict['Total']
        elif (flag == 'stargcount'):
            get_count = mroute_dict['(*,G)_routes']
        elif (flag == 'sgcount'):
            get_count = mroute_dict['(S,G)_routes']
        elif (flag == 'starg-pfxcount'):
            get_count = mroute_dict['(*,G-prefix)_routes']
        if (count != get_count):
             log.info('Iteration: {3} - Expected mroutes not present,Looking for:{0},found:{1},expected:{2}'.\
                            format(flag,get_count,count,iteration))
        else:
             verified=True

        if (verified or iteration==verify_iterations-1):
            break

        time.sleep(verify_interval)

    if verified:
        testResult('pass','verifyMrouteCount passed',log)   
    else:
        testResult('fail','verifyMrouteCount failed',log)   

#########################################################################################


class verifyIgmpSnoopingCount ():

  def __init__(self,hdl,log,*args, **igmp_dict):
    self.result='pass'

    # Sample Usage
    # verifies the count of snooping group entries for a given vlan|group|source or count of all
    # snooping entries
    # Another option is to pass snooping entries in form of dict with different value for diff vlan
    # and it can verify that as well
    
    # count is passed as string
    # igmp_dict ={}
    # igmp_dict['2']={}
    # igmp_dict['2']['(*,G)-Count']='52'
    # igmp_dict['2']['(S,G)-Count']='0'

    # verifyIgmpSnoopingCount(hdl,log,,'-count 10 -flag sgcount -verify_iterations 10')
    # verifyIgmpSnoopingCount(hdl,log,'-count 11 -flag stargcount')
    # verifyIgmpSnoopingCount(hdl,log,'-count 12 -flag total -vlan 20')
    # verifyIgmpSnoopingCount(hdl,log,'-count 12', value=igmp_dict)
 
    arggrammar={}
    arggrammar['vlan']='-type str'
    arggrammar['count']='-type str -required True'
    arggrammar['group']='-type str'
    arggrammar['flag']='-type str -choices ["starGCount","sGCount","Total"] -default Total'
    arggrammar['source']='-type str'
    arggrammar['verify_iterations']='-type int -default 1'
    arggrammar['verify_interval']='-type int -default 15'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    cmd = 'show ip igmp snooping groups'
    options =''
    count = parse_output.count
    if parse_output.flag:
        flag = parse_output.flag.lower()
    if parse_output.vlan:
        options += ' -vlan ' + parse_output.vlan
        cmd += ' vlan ' + parse_output.vlan
    if parse_output.source:
        options += ' -source ' + parse_output.source
        cmd += ' ' + source
    if parse_output.group:
        options += ' -group ' + parse_output.group
        cmd += ' ' + group
    verify_iterations=parse_output.verify_iterations
    verify_interval=parse_output.verify_interval

    verified=False
    for iteration in range(verify_iterations):
        # Get Actual output from switch
        out_snoop_dict = getIgmpSnoopingSummaryDict (hdl,log, options)
        # if igmp_dict is passed then user expects match against that else verify against appr flag
        if igmp_dict:
            if (compareVars(igmp_dict['value'],out_snoop_dict,log) != 'pass'):
                log.info('Iteration {0}: Expected value for IGMP Snooping entries did not match'.format(iteration))
            else:
                verified=True
        elif (flag == 'sgcount'):
            if (count != out_snoop_dict['TotalSG']):
                log.info('Iteration {0}: Expected value for Total (S,G) Count does not match,expected:{1},found={1}'.\
                               format(iteration,count,out_snoop_dict['TotalSG']))
            else:
                verified=True
        elif (flag == 'stargcount'):
            if (count != out_snoop_dict['TotalStarG']):
                log.info('Iteration {0}: Expected value for Total (*,G) Count does not match,expected:{1},found={2}'.\
                               format(iteration,count,out_snoop_dict['TotalStarG']))
            else:
                verified=True
        elif (flag == 'total'):
            total = str(int(out_snoop_dict['TotalSG'])+int(out_snoop_dict['TotalStarG']))
            if (count != total):
                log.info('Iteration {0}: Expected value for Total (S,G)/(*,G) Count does not match,expected:{1},found={2}'.\
                               format(iteration,count,total))
            else:
                verified=True

        if (verified or iteration==verify_iterations-1):
            break

        time.sleep(verify_interval)
            
    if verified:
        testResult('pass','verifyIgmpSnoopingCount passed',log)
    else:
        testResult('fail','verifyIgmpSnoopingCount failed',log)



#======================================================================================#
# verifySystemResources - Method to verify system resources information. If argument 
# '-snmmp 1' is provided, system resources info will be verified between CLI and snmp output
# if the argument '**dict' is given, system resoruce info is verified against the specified 
# threshold from dict. By default, CPU idle usage and load average in 5 mins are always 
# verified against the default threshold if no threshold given by user.
# By default, system resource verification can only pass if 5 consecutive checks pass. If one of 
# them fails, it will continue to another 5 consecutive checks. The verification will be declared
# as failure after verification is tried in 5 minutes.
# mandatory args: hdl, log
# Optional args: '-snmp 1','-module 3', '-fex 110', '-loop 5', '-interval 5', '-duration 300', \
#                dict=threshold_dict
# e.g. threshold_dict: 
# Expected threshold on module 1: Memory usage should have free >20%, used <80%, cpu kernel < 30%, idle > 40%, user <30%, load average 5 min<0.30, 15 min <0.30 and 1 min<0.30
{1: {'Memory usage': {'free': '20%', 'used': '80%'}, 'CPU states': {'kernel': '30%', 'idle': '40%', 'user': '30%'}, 'Load average': {'5 minutes': '0.30', '15 minutes': '0.30', '1 minute': '0.30'}}}


class verifySystemResources():
  "  If 'all' is used as module key, user given threshold will be the same across all modules\
  {'all': {'Memory usage': {'free': '20%', 'used': '80%'}, 'CPU states': {'kernel': '30%', 'idle': '40%', 'user': '30%'}, 'CPU core states': {'kernel': '30%', 'idle': '40%', 'user': '30%'}, 'Load average': {'5 minutes': '0.30', '15 minutes': '0.30', '1 minute': '0.30'}}}\
  \
  Usage Examples: verifySystemResources(hdl, log) - Verify system resources on SUPs from CLI\
  verifySystemResources(hdl, log,'-loop 3','-interval 5', '-duration 60')\
  -Verification passes in 3 consecutive successful tries\
  with 5 second interval,otherwise the total duration will\
  be 60 seconds till test is declared as failure\
  verifySystemResources(hdl, log,'-module 1,3,4') - Verify system resources on\
  module 1,3 and 4.\
  verifySystemResources(hdl, log,'-snmmp 1') - Verifies system resources\
  from CLI as well as snmp\
  verifySystemResources(hdl, log,dict=threshold_dict) - Verify system resources\
  against the threshold as in dict"
  def __init__(self,hdl, log, *args, **kargs):
    self.result='pass'
    arggrammar={}
    arggrammar['snmp']='-type int'
    arggrammar['module']='-type str -format [0-9,]+'
    arggrammar['fex']='-type str -format [0-9,]+'
    arggrammar['loop']='-type int'
    arggrammar['interval']='-type int'
    arggrammar['duration']='-type int'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
    #Default threshold for cpu idle and load average in 5 minutes
    #Both will be verified when user does not specify threshold
    CPU_IDLE_THRESHOLD=20.0
    LOAD_AVG_5_MINS=0.80
    MEM_USAGE_THRESHOLD=0.90

    #Default loop, interval and duration
    if ns.loop:
        loop=ns.loop
    else:
        loop=5
    if ns.interval:
        interval=ns.interval
    else:
        interval=5
    if ns.duration:
        duration=ns.duration
    else:
        duration=300
 
    #Any failure reset the variable of *tries* to be 0.
    #If *tries* reaches to *loop* without any failure, the test passes
    tries=0   
    #iteration can reach up to duration/interval before test fails
    iteration=0

    while (iteration<duration/interval):
        result=True
        #verify the basics in the system resources info from CLI
        if ns.module and not ns.fex:
            out_dict=getSystemResourcesDict(hdl,log,'-module '+ns.module)
        elif ns.fex and not ns.module:    
            out_dict=getSystemResourcesDict(hdl,log,'-fex '+ns.fex)
        elif ns.fex and ns.module:
            out_dict=getSystemResourcesDict(hdl,log,'-module '+ns.module,'-fex '+ns.fex)
        else:
            out_dict=getSystemResourcesDict(hdl,log)  
        if not out_dict:
            if hdl.device_type == 'sTOR' or hdl.device_type == 'EOR':
               testResult('fail','Unable to get system resoruce output on {0}'.format(hdl.switchName),log)
            return None
        tmp_dict={}
        tmp1_dict={}
        for mod in out_dict.keys():
            mem_pat='[0-9]+K'
            total= re.sub('K','',out_dict[mod]['Memory usage']['total'])
            total=float(total)
            free= re.sub('K','',out_dict[mod]['Memory usage']['free'])
            free=float(free)
            used= re.sub('K','',out_dict[mod]['Memory usage']['used'])
            used=float(used)
            #if (total!=used+free):
            #    testResult('fail','total memory usage is not equal to sum of free and used on on module {0} of {1}'.format(mod,hdl.switchName),log)        
            #    result=False
            if (not kargs):
               # or (mod not in kargs['dict'].keys()) or \
               #('Memory usage' not in kargs['dict'][mod].keys()):
                mem_usage=float(used)/float(total)
                if mem_usage>=MEM_USAGE_THRESHOLD:
                    testResult('fail','Memory usage: {3} exceeded the threshold of {2} on module {0} of {1}'.format(mod,hdl.switchName,MEM_USAGE_THRESHOLD,mem_usage),log)
                    result=False

            kernel=re.sub('%','',out_dict[mod]['CPU states']['kernel'])
            kernel=float(kernel)
            idle=re.sub('%','',out_dict[mod]['CPU states']['idle'])
            idle=float(idle)
            user=re.sub('%','',out_dict[mod]['CPU states']['user'])
            user=float(user)
            #if (kernel<0 or idle<0 or user<0):
            #    testResult('fail','CPU states is negative on module {0} of {1}'.format(mod,hdl.switchName),log)
            #    result=False
            #if (kernel+idle+user!=100.0):
            #    testResult('fail','total CPU usage is not equal to 100% on module {0} of {1}'.format(mod,hdl.switchName),log)
            #    result=False
            if (not kargs):
               # or (mod not in kargs['dict'].keys()) or \
               #('CPU states' not in kargs['dict'][mod].keys()) or \
               #('idle' not in kargs['dict'][mod]['CPU states'].keys()):
                if (idle<=CPU_IDLE_THRESHOLD):
                    log.info('CPU usage idle {0} is below default threshold {1} on module {2} of {3}'\
                              .format(idle,CPU_IDLE_THRESHOLD,mod,hdl.switchName))
                    result=False

            load5=float(out_dict[mod]['Load average']['5 minutes'])
            load15=float(out_dict[mod]['Load average']['15 minutes'])
            load1=float(out_dict[mod]['Load average']['1 minute'])
            #if (load5<0 or load15<0 or load1<0):
            #    testResult('fail','Load average is negative on module {0} of {1}'.format(mod,hdl.switchName),log)
            #    result=False
            #if (load5>1 or load15>1 or load1>1):
            #    testResult('fail','Load average is higher than 1 on module {0} of {1}'.format(mod,hdl.switchName),log)
            #    result=False
     
            if (not kargs):
               # or (mod not in kargs['dict'].keys()) or \
               #('Load average' not in kargs['dict'][mod].keys()) or \
               #('5 minutes' not in kargs['dict'][mod]['Load average'].keys()):  
                if (load5>=LOAD_AVG_5_MINS):
                    log.info('Load average in 5 minutes {0} is higher than default threshold {1} on module {2} of {3}'\
                        .format(load5,LOAD_AVG_5_MINS,mod,hdl.switchName))
                    result=False       
    
            tmp1_dict[mod]={}    
            for cpu_core in out_dict[mod]['CPU core states']:
                tmp1_dict[mod][cpu_core]={}
                kernel=re.sub('%','',out_dict[mod]['CPU core states'][cpu_core]['kernel'])
                tmp1_dict[mod][cpu_core]['kernel']=float(kernel)
                idle=re.sub('%','',out_dict[mod]['CPU core states'][cpu_core]['idle'])
                tmp1_dict[mod][cpu_core]['idle']=float(idle)
                user=re.sub('%','',out_dict[mod]['CPU core states'][cpu_core]['user'])
                tmp1_dict[mod][cpu_core]['user']=float(user)

            tmp={mod:{'total':total,'free':free,'used':used,'kernel':kernel,'idle':idle,'user':user,
                     'load5':load5,'load15':load15, 'load1':load1}}
            tmp_dict.update(tmp)
        
    
        #Verify system resources info against threshold 
        if kargs:
            dict=kargs['dict']
            if 'all' in dict.keys():
            #Replicate values of dict for each key in out_dict
                t_dict={}
                for key in out_dict.keys():
                    temp={key:dict['all']}
                    t_dict.update(temp)
                dict=t_dict 
            for mod in dict.keys():
                if mod not in out_dict.keys():
                    testResult('fail','module {0} could not be found on {1}'.format(mod,hdl.switchName),log)
                    result=False
                    continue
                for category in dict[mod].keys():
                    if category not in out_dict[mod].keys():
                        testResult('fail','System resource category {0} is not available'.format(category),log)
                        result=False
                        continue
                    for type in dict[mod][category]:
                        if category=='CPU core states':
                            for core in out_dict[mod][category]:
                                if type not in out_dict[mod][category][core].keys():
                                    self.log.error('System resource info of {0} in category {1} in core {2} not available'\
                                               .format(type,category,core))
                                    result=False
                                    continue
                        else:
                            if type not in out_dict[mod][category].keys():
                                self.log.error('System resource info of {0} in category {1} not available'\
                                           .format(type,category))
                                result=False
                                continue
                        if type=='total':
                            continue
                        threshold=dict[mod][category][type]
                        if type=='free':
                            free_threshold=float(re.sub('%','',threshold))
                            percent=tmp_dict[mod]['free']/tmp_dict[mod]['total']
                            if percent<=free_threshold/100:
                                log.info('fail','Free memory usage {0} is below threshold {1}% on module {2} of {3}'\
                                           .format(percent, free_threshold,mod,hdl.switchName))
                                result=False
                        if type=='used':
                            used_threshold=float(re.sub('%','',threshold))
                            percent=tmp_dict[mod]['used']/tmp_dict[mod]['total']
                            if percent>=used_threshold/100:
                                log.info('Used memory usage {0} is above threshold {1}% on module {2} of {3}'\
                                           .format(percent, used_threshold,mod,hdl.switchName))
                                result=False

                        if type=='kernel' and category=='CPU states':
                            kernel_threshold=float(re.sub('%','',threshold))
                            if tmp_dict[mod]['kernel']>=kernel_threshold:
                                log.info('Kernel CPU usage {0}% is above threshold {1}% on module {2} of {3}'\
                                           .format(tmp_dict[mod]['kernel'],kernel_threshold,mod,hdl.switchName))
                                result=False
                        if type=='idle' and category=='CPU states':
                            idle_threshold=float(re.sub('%','',threshold))
                            if tmp_dict[mod]['idle']<=idle_threshold:
                                log.info('Idle CPU usage {0}% is below threshold {1}% on module {2} of {3}'\
                                           .format(tmp_dict[mod]['idle'],idle_threshold,mod,hdl.switchName))
                                result=False
                        if type=='user' and category=='CPU states':
                            user_threshold=float(re.sub('%','',threshold))
                            if tmp_dict[mod]['user']>=user_threshold:
                                log.info('user CPU usage {0}% is above threshold {1}% on module {2} of {3}'\
                                           .format(tmp_dict[mod]['user'], user_threshold,mod,hdl.switchName))
                                result=False

                        if type=='kernel' and category=='CPU core states':
                            kernel_threshold=float(re.sub('%','',threshold))
                            for cpu_core in tmp1_dict[mod]:
                                if tmp1_dict[mod][cpu_core]['kernel']>=kernel_threshold:
                                    log.info('Kernel CPU core {4} usage {0}% is above threshold {1}% on module {2} of {3}'\
                                        .format(tmp1_dict[mod][cpu_core]['kernel'],kernel_threshold,mod,hdl.switchName,cpu_core))
                                    result=False
                        if type=='idle' and category=='CPU core states':
                            idle_threshold=float(re.sub('%','',threshold))
                            for cpu_core in tmp1_dict[mod]:
                                if tmp1_dict[mod][cpu_core]['idle']<=idle_threshold:
                                    log.info('Idle CPU core {4} usage {0}% is below threshold {1}% on module {2} of {3}'\
                                        .format(tmp1_dict[mod][cpu_core]['idle'],idle_threshold,mod,hdl.switchName,cpu_core))
                                    result=False
                        if type=='user' and category=='CPU core states':
                            user_threshold=float(re.sub('%','',threshold))
                            for cpu_core in tmp1_dict[mod]:
                                if tmp1_dict[mod][cpu_core]['user']>=user_threshold:
                                    log.info('user CPU core {4} usage {0}% is above threshold {1}% on module {2} of {3}'\
                                        .format(tmp1_dict[mod][cpu_core]['user'], user_threshold,mod,hdl.switchName,cpu_core))
                                    result=False

                        if type=='5 minutes':
                            load5_threshold=float(threshold)
                            if tmp_dict[mod]['load5']>=load5_threshold:
                                log.info('Load average in 5 minutes {0} is above threshold {1} on module {2} of {3}'\
                                           .format(tmp_dict[mod]['load5'], load5_threshold,mod,hdl.switchName))
                                result=False
                        if type=='15 minutes':
                            load15_threshold=float(threshold)
                            if tmp_dict[mod]['load15']>=load15_threshold:
                                log.info('Load average in 15 minutes {0} is above threshold {1} on module {2} of {3}'\
                                           .format(tmp_dict[mod]['load15'], load15_threshold,mod,hdl.switchName))
                                result=False
                        if type=='1 minute':
                            load1_threshold=float(threshold)
                            if tmp_dict[mod]['load1']>=load1_threshold:
                                log.info('Load average in 1 minute {0} is above threshold {1} on module {2} of {3}'\
                                           .format(tmp_dict[mod]['load1'], load1_threshold,mod,hdl.switchName))
                                result=False
          
        #TO DO       
        #verify system resources info through SNMP

        if result:
             log.info('System resource verification passes in iteration {0} on {1}'.format(iteration,hdl.switchName))
             tries+=1
             if tries==loop:
                  log.info('System resource is verified successfully on {0}'.format(hdl.switchName))
                  return None
        else:
             tries=0
             log.info('System resource verification fails in iteration {0} on {1}'.format(iteration,hdl.switchName))
        iteration+=1
        time.sleep(interval)
    #End of while loop
    testResult('fail','System resource verification fails in duration of {0} seconds on {1}'.format(duration,hdl.switchName),log)
    return None               



class verifyVrrp():
  "  verifyVrrp - Method to verify the state of VRRP instances configured\
  \
  mandatory args: hdl, log\
  \
  Optional args: vrrplist or vrrptuple or vrrpdict\
  Usage Examples: verifyVrrp(hdl, log) - Verifies all VRRP instannces are in Master/Backup state\
  verifyVrrp(hdl, log, expecteddict=vrrpdict) - Verifies against vrrpdict. Dict is same as getVrrpv2Dict\
  verifyVrrp(hdl, log, '-vrrplist 1,3') - Verifies VRRP instances 1,3  are in Master/Backup state.\
  If same VRRP instance is configured under multiple interfaces, this will validate against all\
  the interfaces where same VRRP instance is configure\
  verifyVrrp(hdl, log, '-vrrptuple (Vlan100 1, Ethernet1/10 1)') - Verifies VRRP instances Vlan100,1\
  and Ethernet1/10,1 are in Master/Backup state."
  def __init__(self,hdl, log, *args, **vrrpdict):
    self.result='pass'

    arggrammar={}
    arggrammar['vrrplist']=''
    arggrammar['vrrptuple']=''
    argoptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    showvrrpdict=getVrrpv2Dict(hdl,log)
    result=True

    if argoptions.vrrplist:
        for vrrp in strtolist(argoptions.vrrplist):
            keys=getKeys(vrrp,showvrrpdict.keys())
            if len(keys):
                for key in keys:
                   if showvrrpdict[key]['State'] in ['Master','master','Backup','backup']:
                      log.info("{0} is in {1}".format(key,showvrrpdict))
                   else:
                      log.error("{0} is expected in Master/Backup state but actual state is {1} ".format(key,showvrrpdict[key]['State']))
                      result=False
            else:
                log.error("No matching entry for {0} found in {1}".format(vrrp,showvrrpdict))
                result=False
        if result:
            testResult('pass','All the given VR instances {0} is found to be in Master/Backup state'.format(argoptions.vrrplist),log)
        else:
             testResult('Fail','Some or all of the given VR instances {0} is found to be not in Master/Backup state'.format(argoptions.vrrplist),log)

    if argoptions.vrrptuple:
        for vrrp in strtolistoftuple(argoptions.vrrptuple):
            if vrrp in showvrrpdict.keys():
               if showvrrpdict[vrrp]['State'] in ['Master','Backup']:
                  log.info("{0} is in {1}".format(vrrp,showvrrpdict))
               else:
                  log.error("{0} is expected in Master/Backup state but actual state is {1} ".format(vrrp,showvrrpdict[vrrp]['State']))
                  result=False
            else:
                log.error("No matching entry for {0} found in {1}".format(vrrp,showvrrpdict))
                result=False
        if result:
            testResult('pass','All the given VR instances {0} is found to be in Master/Backup state'.format(argoptions.vrrptuple),log)
        else:
             testResult('Fail','Some or all of the given VR instances {0} is found to be not in Master/Backup state'.format(argoptions.vrrptuple),log)


    if vrrpdict: 
        if re.search('pass',compareVars(vrrpdict['expecteddict'],showvrrpdict,log)):
            testResult('pass','{0} is subset of {1} as expected'.format(vrrpdict['expecteddict'],showvrrpdict),log)
        else:
            testResult('fail','{0} is expected  to be subset of {1} but actual is not'.format(vrrpdict['expecteddict'],showvrrpdict),log)

    if not argoptions.vrrplist and not argoptions.vrrptuple and not vrrpdict:
        for key in showvrrpdict.keys():
            if showvrrpdict[key]['State'] in ['Master','master','Backup','backup']:
                log.info("{0} is in {1} as expected".format(key,showvrrpdict[key]['State']))
            else:
                log.info("{0} is expected to Master/Backup but actually in {1} ".format(key,showvrrpdict[key]['State']))
                result=False
        if result and len(showvrrpdict.keys()):
            testResult('pass','All VRRP instances are in Master/Backup state as expected',log)
        elif len(showvrrpdict.keys()):
            testResult('pass','Some or All VRRP instances are not in Master/Backup state',log)
        else:
            testResult('fail','No VRRP instances found',log)
        



class verifyHsrp():
  "  verifyHsrp - Method to verify the state of HSRP instances configured\
  \
  mandatory args: hdl, log\
  \
  Optional args: hsrplist or or hsrptuple or hsrpdict\
  Usage Examples: verifyHsrp(hdl, log) - Verifies all HSRP instannces are in Active/Standby state\
  verifyHsrp(hdl, log, expecteddict=hsrpdict) - Verifies against hsrpdict. Dict is same as getHsrpDict\
  verifyHsrp(hdl, log, '-hsrplist 1,3') - Verifies HSRP instances 1,3  are in Active/Standby state.\
  If same VRRP instance is configured under multiple interfaces, this will validate against all\
  the interfaces where same HSRP instance is configured\
  verifyVrrp(hdl, log, '-hsrptuple (Vlan100 1), (Ethernet1/10 1)') - Verifies HSRP instances Vlan100,1\
  and Ethernet1/10,1 are in Active/Standby state."
  def __init__(self,hdl, log, *args, **hsrpdict):
    self.result='pass'

    arggrammar={}
    arggrammar['hsrplist']=''
    arggrammar['hsrptuple']=''
    argoptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    showhsrpdict=getHsrpDict(hdl,log)
    result=True

    if argoptions.hsrplist:
        for hsrp in strtolist(argoptions.hsrplist):
            keys=getKeys(hsrp,showhsrpdict.keys())
            if len(keys):
                for key in keys:
                   if showhsrpdict[key]['state'] in ['Active','Standby']:
                      log.info("{0} is in {1}".format(key,showhsrpdict))
                   else:
                      log.error("{0} is expected in Active/Standby state but actual state is {1} ".format(key,showhsrpdict[key]))
                      result=False
            else:
                log.error("No matching entry for {0} found in {1}".format(hsrp,showhsrpdict))
                result=False
        if result:
            testResult('pass','All the given VR instances {0} is found to be in Active/Standby state'.format(argoptions.hsrplist),log)
        else:
             testResult('Fail','Some or all of the given VR instances {0} is found to be not in Active/Standby state'.format(argoptions.hsrplist),log)

    if argoptions.hsrptuple:
        for hsrp in strtolistoftuple(argoptions.hsrptuple):
            if hsrp in showhsrpdict.keys():
               if showhsrpdict[hsrp]['state'] in ['Active','Standby']:
                  log.info("{0} is in {1}".format(hsrp,showhsrpdict))
               else:
                  log.error("{0} is expected in Active/Standby state but actual state is {1} ".format(hsrp,showhsrpdict[key]))
                  result=False
            else:
                log.error("No matching entry for {0} found in {1}".format(hsrp,showhsrpdict))
                result=False
        if result:
            testResult('pass','All the given VR instances {0} is found to be in Active/Standby state'.format(argoptions.hsrptuple),log)
        else:
             testResult('Fail','Some or all of the given VR instances {0} is found to be not in Active/Standby state'.format(argoptions.hsrptuple),log)


    if hsrpdict: 
        if re.search('pass',compareVars(hsrpdict['expecteddict'],showhsrpdict,log)):
            testResult('pass','{0} is subset of {1} as expected'.format(hsrpdict['expecteddict'],showhsrpdict),log)
        else:
            testResult('fail','{0} is expected  to be subset of {1} but actual is not'.format(hsrpdict['expecteddict'],showhsrpdict),log)

    if not argoptions.hsrplist and not argoptions.hsrptuple and not hsrpdict:
        for key in showhsrpdict.keys():
            if showhsrpdict[key]['state'] in ['Active','Standby']:
                log.info("{0} is in {1} as expected".format(key,showhsrpdict[key]['state']))
            else:
                log.info("{0} is expected to Active/Standby but actually in {1} ".format(key,showhsrpdict[key]['state']))
                result=False
        if result and len(showhsrpdict.keys()):
            testResult('pass','All VRRP instances are in Active/Standby state as expected',log)
        elif len(showhsrpdict.keys()):
            testResult('pass','Some or All VRRP instances are not in Master/Backup state',log)
        else:
            testResult('fail','No VRRP instances found',log)





class verifyVpcMacConsistencyBetweenPeers():
  "  verifyVpcMacConsistencyBetweenPeers- Method to verify the mac entries on vpcs on peers\
  \
  mandatory args: hdl, log\
  \
  Optional args: vpc or list of vpcs\
  Usage Examples: verifyVpcMacConsistencyBetweenPeers(hdl1, hdl2, log)\
  verifyVpcMacConsistencyBetweenPeers(hdl1, hdl2, log, '-vpc 3')\
  verifyVpcMacConsistencyBetweenPeers(hdl1, hdl2, log, '-vpc 1,2,3')"
  def __init__(self,hdl1, hdl2, log, *args):
    self.result='pass'
    # Verifies the mac tables are same between 2 vpc peers on vpcs
    arggrammer={}
    arggrammer['vpc']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammer,'namespace')
   
    # Get vPC dictionaries from both peer switches
    vpc_get_dict1=getVpcDict(hdl1,log)
    vpc_get_dict2=getVpcDict(hdl2, log)
    #Get list of vpcs up on both peers
    vpc_up_list1=getVpcUpList(hdl1, log)
    vpc_up_list2=getVpcUpList(hdl2, log)
    
    # If vpc_list is given use it, otherwise use all vpcs up
    if parse_output.vpc:
       vpc_list=parse_output.vpc.split(',')
    else:
        if vpc_up_list1==vpc_up_list2:
           vpc_list=vpc_up_list1
        else:
            testResult('fail','One or more vpcs are down on one of the peers', log)
            return
            
    for vpc in vpc_list:
       if vpc not in vpc_up_list1:
           testResult('fail','Vpc {0} is not up on {1}'.format(vpc, hdl1.switchName),log)
       elif vpc not in vpc_up_list2:
           testResult('fail','Vpc {0} is not up on {1}'.format(vpc, hdl2.switchName),log)
       else:
            #Get mac addresss table for interface po of the vpc on both peers
            mac1args='-dynamic -interface {0}'.format(vpc_get_dict1[vpc]['Port'])
            mac2args='-dynamic -interface {0}'.format(vpc_get_dict2[vpc]['Port'])
            mac1=getMacAddressTableDict(hdl1, log, mac1args)
            mac2=getMacAddressTableDict(hdl2, log, mac2args)
              
            #Create new dictionary by removing age
            newdict1=removeColumns(mac1, 'age','Flag')
            newdict2=removeColumns(mac2, 'age','Flag')
                       
            #Compare dictionaries are same
            if newdict1==newdict2:
                log.info('PASSED:Mac tables are in sync on vpc {0}'.format(vpc))
            else:
                #When dictionaries are not same use compareVars to see the mismatch in log
                compareVars(newdict1, newdict2, log, '-equal' )
                testResult('fail','Mac tables are not in sync on vpc {0}'.format(vpc),log)


class verifyMacConsistency():
    """verifyMacConsistency- Method to verify the mac entries between software and HW\
    mandatory args: hdl, log  \
    Optional args: vpc or list of vpcs\
    Usage Examples: verifyVpcMacConsistencyBetweenPeers(hdl1, hdl2, log)\
    verifyMacConsistency(hdl,log, '-type static')\
    verifyMacConsistency(hdl,log)
    """

    def __init__(self,hdl,log,*args):
        self.result='pass'
        # Verifies the mac tables are same between 2 vpc peers on vpcs
        arggrammer={}
        arggrammer['static']='-type bool'
        arggrammer['dynamic']='-type bool'
        arggrammer['interface']='-type str'
        arggrammer['module']='-type int -required True'
        arggrammer['vlan']='-type str'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammer,'namespace')
        args = args[0]
        mac_addresses = {}
        # Get mac address table from SW (l2fm)
        mac_addresses['sw']=getMacAddressTableDict(hdl,log,args)
        # if static or dynamic or passed then append them with flag
        args.replace('-dynamic','-flag dynamic')
        args.replace('-static','-flag static')
        mac_addresses['hw']=getHardwareMacTableDict(hdl,log,args)
        if compareVars(mac_addresses['sw'].keys(),mac_addresses['hw'].keys(),log, '-equal') != 'pass':
            self.result = 'fail'
            testResult('fail','Mac addresses are not in sync between sw and hw on {0}'\
                           .format(hdl.switchName),log)
        else:
            for key in mac_addresses['hw'].keys():
                if int(mac_addresses['hw'][key]['mac_type']) == 1:
                    mac_type = 'static'
                else:
                    mac_type = 'dynamic'
                if mac_addresses['sw'][key]['Type'] != mac_type:
                    self.result ='fail'
                    testResult('fail','Mac Type not in sync for {0} between sw and hw on {1}'\
                                   .format(key,hdl.switchName),log)
        if (self.result =='pass'):
            testResult('pass','Mac addresses are in sync between sw and hw on {0}'.format(hdl.switchName),log)
              

### VxLAN verification methods ###
class verifyNveStats():
  """Added by sandesub"""
  def __init__(self,hdl,log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['rx_ucast']='-type str' 
    arggrammar['tx_ucast']='-type str' 
    arggrammar['rx_mcast']='-type str' 
    arggrammar['tx_mcast']='-type str' 
    arggrammar['interval']='-type int -default 10' 
    arggrammar['iterations']='-type int -default 1' 
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

class verifyNveVni():
  """Added by sandesub"""
  def __init__(self,hdl,log, *args):
    self.result='pass'
    arggrammar={}
    #arggrammar['intf']='-type str -required True' 
    arggrammar['vni']='-type str -required True' 
    arggrammar['mcast_group']='-type str' 
    arggrammar['state']='-type str' 
    arggrammar['interval']='-type int -default 10' 
    arggrammar['iterations']='-type int -default 1' 
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    #intf=ns.intf
    vni=ns.vni
    output=getNveVniDict(hdl,log)[vni]
    #output_vni=output['VNI']
    output_mcast_group=output['Multicast_Group']
    output_state=output['VNI_State']
    #if ns.vni:
      #if output_vni == ns.vni:
        #testResult('pass','expected VNI {0} matches with actual VNI {1} on switch'.format(ns.vni,output_vni),log)
      #else:
        #testResult('fail','expected VNI {0} DOES NOT match with actual VNI {1} on switch'.format(ns.vni,output_vni),log)
        #self.result='fail'
    if ns.mcast_group:
      if output_mcast_group == ns.mcast_group:
        testResult('pass','expected mcast group {0} matches with actual mcast group {1} on switch'.format(ns.mcast_group,output_mcast_group),log)
      else:
        testResult('fail','expected mcast group {0} DOES NOT match with actual mcast group {1} on switch'.format(ns.mcast_group,output_mcast_group),log)
        self.result='fail'
    if ns.state:
      if output_state == ns.state:
        testResult('pass','expected VNI state {0} matches with actual VNI state {1} on switch'.format(ns.state,output_state),log)
      else:
        testResult('fail','expected VNI state {0} DOES NOT match with actual VNI state {1} on switch'.format(ns.state,output_state),log)
        self.result='fail'

class verifyNvePeers():
  """Added by sandesub"""
  def __init__(self,hdl,log, *args):
    self.result='pass'
    arggrammar={}
    #arggrammar['vni']='-type str -required True' 
    arggrammar['peer_ip']='-type str' 
    arggrammar['state']='-type str -default Up' 
    arggrammar['interval']='-type int -default 10' 
    arggrammar['iterations']='-type int -default 1' 
    arggrammar['negative']='-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    peer_ip=ns.peer_ip
    state=ns.state
    #vni=ns.vni
    output_dict=getNvePeersDict(hdl,log)
    if not ns.negative:
        try:
            nve_intf = output_dict[peer_ip]['Interface']
            peer_state = output_dict[peer_ip]['Peer_State']
            if nve_intf == 'Nve1' and peer_state == state:
                testResult('pass','Peer {0} is discovered with state {1} on interface {2}'.format(peer_ip,peer_state,nve_intf),log)
        except KeyError as e:
            log.error('key does not exist "%s"' % str(e))
            testResult('fail','Peer {0} is NOT discovered'.format(peer_ip),log)
    else:
        log.info('This is negative case, where we dont expect to see peer')
        try:
            nve_intf = output_dict[peer_ip]['Interface']
            if nve_intf == 'Nve1':
                testResult('fail','Peer {0} should NOT be discovered on interface {1}'.format(peer_ip,nve_intf),log)
        except KeyError as e:
            log.error('key does not exist "%s"' % str(e))
            testResult('pass','Peer {0} is NOT discovered'.format(peer_ip),log)
        
  

class verifySpanningTreeMode():
  "  Added by sandesub\
  Description: checks the STP mode configured on the switch\
  accepted modes: mst, rapid-pvst\
  Sample Usage:\
  verifySpanningTreeMode(hdl,log) - checks by default if mode is rapid-pvst\
verifySpanningTreeMode(hdl,log, '-mode mst') - check if mode is mst"
  def __init__(self,hdl, log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['mode']='-type str -choices ["rapid-pvst", "mst"] -default rapid-pvst'
    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments for verify function')
        return None
    if options_namespace.mode:
        input_mode=options_namespace.mode
    output_mode = utils.getSpanningTreeMode(hdl,log)
    if (input_mode == output_mode):
        testResult('pass','expected STP mode {0} matches with actual STP mode {1} on switch'.format(input_mode,output_mode),log)
    else:
        testResult('fail','expected STP mode {0} DOES NOT MATCH with actual STP mode {1} on switch'.format(input_mode,output_mode),log)
        self.result='fail'
         

class verifySpanningTreeInconsistentPorts():
  "  Added by renbalaj\
  Description: checks the STP mode configured on the switch\
  accepted state: enabled, disabled \
  Sample Usage:\
  verifySpanningTreeInconsistentPorts(hdl,log,'-interface eth1/1')   "

  def __init__(self,hdl, log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['interface']='-type str '
    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments for verify function')
        return None
    if options_namespace.interface:
        input_interface=options_namespace.interface
    output_interface_list  = utils.getSpanningTreeInconsistentPorts(hdl,log)

    log.info (' Input interface {0} '.format(input_interface))
    log.info (' Outputs interface {0} '.format(output_interface_list))
    verify =  input_interface in output_interface_list

    if verify:
        testResult('pass','Pass: Port {0} is  found in spanning-tree inconsistent ports {1} on switch {2} '.format(input_interface,output_interface_list,hdl.switchName),log)
    else:
        testResult('fail','Fail: Port {0} is not found in spanning-tree inconsistent ports {1} on switch {2} '.format(input_interface,output_interface_list,hdl.switchName),log)
        self.result='fail'



class verifySpanningTreeBridgeAssuranceState():
  "  Added by renbalaj\
  Description: checks the STP mode configured on the switch\
  Sample Usage:\
  verifySpanningTreeBridgeAssuranceState(hdl,log) - checks by default if state is enabled \
  verifySpanningTreeBridgeAssuranceState(hdl,log, '-state enabled ') - check BA is enabled "
  def __init__(self,hdl, log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['state']='-type str '
    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments for verify function')
        return None
    if options_namespace.state:
        input_state=options_namespace.state
    output_state = utils.getSpanningTreeBridgeAssuranceState(hdl,log)
    log.info (' Input state {0} '.format(input_state))
    log.info (' Outputs state {0} '.format(output_state))
    if (input_state == output_state):
        testResult('pass','PASS: expected STP state {0} matches with actual STP state {1} on switch {2} '.format(input_state,output_state,hdl.switchName),log)
    else:
        testResult('fail','FAIL: expected STP mode {0} DOES NOT MATCH with actual STP mode {1} on switch {2} '.format(input_state,output_state,hdl.switchName),log)
        self.result='fail'






class verifySpanningTreeVlanStatesCountDict():
  "  Added by sandesub\
  Description: Verifies the total count of blocking/listening/learning/forwarding/STP active ports across all VLANs using the output of show spanning-tree summary totals command on the switch\
  Sample Usage:\
  verifySpanningTreeVlanStatesCountDict(hdl,log,**stp_states_count_dict) - verification across all VLANs\
verifySpanningTreeVlanStatesCountDict(hdl,log, '-vlan <vlan-id>' , **stp_states_count_dict) - verification on specific VLAN\
verifySpanningTreeVlanStatesCountDict(hdl,log, '-vlan <vlan-range>' , **stp_states_count_dict) - verification on specific VLAN"
  def __init__(self,hdl,log, *args, **stp_states_count_dict):
    self.result='pass'
    arggrammar={}
    arggrammar['vlan']='-type str -format [0-9-, ]+' 
    arggrammar['interval']='-type int -default 10' 
    arggrammar['iterations']='-type int -default 1' 
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    iterations=parse_output.iterations
    interval=parse_output.interval
    if stp_states_count_dict:
        loop=0
        while loop<iterations:
            if parse_output.vlan:
                output_stp_states_count_dict = getSpanningTreeVlanStatesCountDict(hdl,log,'-vlan ' + str(parse_output.vlan))
            else:
                output_stp_states_count_dict = getSpanningTreeVlanStatesCountDict(hdl,log)
            if (compareVars(stp_states_count_dict,output_stp_states_count_dict,log) == 'fail'):
                loop+=1
                if loop == iterations: 
                    self.result='fail'
                    testResult('fail','State counts are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(stp_states_count_dict,output_stp_states_count_dict),log)
                else:     
                    time.sleep(interval)
            else:
                break
    else:
                testResult('fail','State counts are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(stp_states_count_dict,output_stp_states_count_dict),log)
                self.result='fail'
                        
class verifyMSpanningTreeVlanStatesCountDict():
  "Description: Verifies the total count of blocking/listening/learning/forwarding/STP active ports across all VLANs using the output of show spanning-tree summary totals command on the switch\
  Sample Usage:\
  verifyMSpanningTreeVlanStatesCountDict(hdl,log,**stp_states_count_dict) - verification across all VLANs"
  def __init__(self,hdl,log, args, **stp_states_count_dict):
    self.result='pass'
    arggrammar={}
    arggrammar['interval']='-type int -default 10'
    arggrammar['iterations']='-type int -default 1'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    iterations=parse_output.iterations
    interval=parse_output.interval
    log.info('##### expected stp states count dic passed to verifyMSpanningTreeVlanStatesCountDict is : {0}'.format(stp_states_count_dict))   
    if stp_states_count_dict:
        loop=0
        while loop<iterations:
            output_stp_states_count_dict = getMSpanningTreeVlanStatesCountDict(hdl,log)
            if (compareVars(stp_states_count_dict,output_stp_states_count_dict,log) == 'fail'):
                loop+=1
                if loop == iterations:
                    self.result='fail'
                    testResult('fail','State counts are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(stp_states_count_dict,output_stp_states_count_dict),log)
                else:
                    time.sleep(interval)
            else:
                break
    else:
                testResult('fail','State counts are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(stp_states_count_dict,output_stp_states_count_dict),log)
                self.result='fail'

class verifySpanningTreePortState():
    """
    verifySpanningTreePortState - Method to verify stp state and role details for a
    given interface  Mandatory args ==\
    -vlan <id>\
    -interface <id>\
    stp_states_dict : stp role and states for the given interface.
    samples below\
    stp_dict['2'] = {}
    stp_dict['2']['state']='FWD'
    stp_dict['2']['role']='Desg'
    or
    stp_dict['1-100'] = {}
    stp_dict['1-100']['state']='FWD'
    stp_dict['1-100']['role']='Desg'
    Sample Usage:
    verifySpanningTreePortState(hdl, log,'-interface eth1/2',**input_dict)
    """
    def __init__(self,hdl,log, *args, **stp_states_dict):
        self.result='pass'
        arggrammar={}
        arggrammar['interface']='-type str -required True'
        arggrammar['interval']='-type int -default 10'
        arggrammar['iterations']='-type int -default 4'

        parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        # Get new expanded list for verififcation
        exp_stp_states_dict ={}
        for key in stp_states_dict.keys():
            vlan_list = strToExpandedList(key)
            for vlan in vlan_list:
                exp_stp_states_dict[vlan] = {}
                # Copy everything else
                for next_key in stp_states_dict[key].keys():
                    exp_stp_states_dict[vlan][next_key] = stp_states_dict[key][next_key]
                    print ('vlan :{0} expect dict is {1} stp state dict is {2}'.format(vlan,exp_stp_states_dict[vlan][next_key],stp_states_dict[key][next_key]))
        output_dict= utils.getSpanningTreePortStateDict(hdl,log,'-interface {0}'.format(parseoutput.interface))
        if exp_stp_states_dict:
            if not utils.loop_until("utils.getSpanningTreePortStateDict",(hdl,log,'-interface {0}'.format(parseoutput.interface)),exp_stp_states_dict,'-iterations {0} -interval {1}'.format(parseoutput.iterations,parseoutput.interval)):
                testResult('fail','STP role and state are INCORRECT for {0} on {1} '\
                               .format(parseoutput.interface,hdl.switchName),log)
            else:
                testResult('pass','STP role and state are CORRECT for {0} on {1} '\
                               .format(parseoutput.interface,hdl.switchName),log)
        else:
            testResult('fail','Input stp_states_dict INCORRECT for {0} on {1} '\
                              .format(parseoutput.interface,hdl.switchName),log)




class verifyMtsBuffersUsage():
  "  verifyMtsBuffersUsage - Method to verify MTS buffer usage.\
  By default the threshold for all of mts queues are 20, if messages of a SAP exceeds the threshold\
  the iteration of check fails. By default, mts buffer usage verification can only pass if\
  5 consecutive checks pass. If one of them fails, it will continue to another 5 consecutive checks.\
  The verification will be declared as failure after verification is tried in 5 minutes.\
  In the case of failure, age of SAP message is checked in mts buffer detail. The messages with\
  age>120 sec is reported.\
  mandatory args: hdl, log\
  Optional args: '-module 3', '-fex 110', '-mts_q_threshold 10', 'ignore_saps 284,176'\
  '-loop 3', '-interval 5', '-duration 60' '-max_q_age 300000'\
  Usage Examples: verifyMtsBuffersUsage(hdl, log) - Verify mts buffer usages on SUPs\
  verifyMtsBuffersUsage(hdl, log,'-loop 3','-interval 5', '-duration 60')\
  -Verification passes in 3 consecutive successful tries\
  with 5 second interval,otherwise the total duration will\
  be 60 seconds till test is declared as failure\
  verifyMtsBuffersUsage(hdl, log,'-module 1,3,4') - Verify mts buffer usage on\
  module 1,3 and 4.\
  verifyMtsBuffersUsage(hdl, log,'-mts_q_threshold 10') - Verifies mts buffer usage\
  test fails when number of queued message is more than 10\
  verifyMtsBuffersUsage(hdl, log,'-ignore_saps 284') - Verify mts buffer usage\
  ignoring buffer leak on sap of 284\
  verifyMtsBuffersUsage(hdl, log,'-max_q_age 300000') - Verify mts buffer usage\
  with max message age threshold set to 120k ms"
  def __init__(self,hdl, log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['module']='-type str -format [0-9,]+'
    arggrammar['fex']='-type str -format [0-9,]+'
    arggrammar['mts_q_threshold']='-type str -format [0-9]+'
    arggrammar['max_q_age']='-type str -format [0-9]+'
    arggrammar['ignore_saps']='-type str -format [0-9,]+'
    arggrammar['loop']='-type str -format [0-9]+'
    arggrammar['interval']='-type str -format [0-9]+'
    arggrammar['duration']='-type str -format [0-9]+'
    exclude_list1=['mts_q_threshold','ignore_saps','loop','interval','duration','mts_q_threshold','max_q_age']
    exclude_list2=['mts_q_threshold','ignore_saps','loop','interval','duration','mts_q_threshold']
    arg1=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'str',exclude_list1,'-')
    arg2=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'str',exclude_list2,'-')
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    #Default threshold of mts buffer queues
    if ns.mts_q_threshold:
        MTS_Q_THRESHOLD=int(ns.mts_q_threshold)
    else:
        MTS_Q_THRESHOLD=20
 
    if ns.max_q_age:
        MAX_Q_AGE=int(ns.max_q_age)
    else: 
        MAX_Q_AGE=300000

    if ns.ignore_saps:
        ignore_saps=strtolist(ns.ignore_saps)
    else:
        ignore_saps=''
    #Default loop, interval and duration
    if ns.loop:
        loop=int(ns.loop)
    else:
        loop=5
    if ns.interval:
        interval=int(ns.interval)
    else:
        interval=5
    if ns.duration:
        duration=int(ns.duration)
    else:
        duration=300
    #Any failure reset the variable of *tries* to be 0.
    #If *tries* reaches to *loop* without any failure, the test passes
    tries=0   
    #iteration can reach up to duration/interval before test fails
    iteration=0
    while (iteration<duration/interval):
        result=True
        out_dict=getMtsBuffersSummaryDict(hdl,log,arg1)
        if not out_dict:
            testResult('fail','Unable to get mts buffer summary output on {0}'.format(hdl.switchName),log)
            return None
        self.failure_list=[]
        self.failure_details=[]
        for mod in out_dict.keys():
            for node in out_dict[mod].keys():
                 for queue in out_dict[mod][node].keys():
                      if out_dict[mod][node][queue]>=MTS_Q_THRESHOLD and \
                         str(node[1]) not in ignore_saps:
                           log.info('Iteration {4}: MTS queue {0} for SAP {1} exceeds MTS_Q_THRESHOLD {5} on module {2} of {3}'\
                                      .format(queue,node,mod,hdl.switchName,iteration,MTS_Q_THRESHOLD))
                           result=False
                           tries=0
                           self.failure_list.append((mod,node[0],str(node[1])))
                           break
         
                 
        if result:
             log.info('Iteration {0}: MTS buffer usage verification passes on {1}'.format(iteration,hdl.switchName))
             tries+=1
             if tries==loop:
                  log.info('MTS buffer usage verification passes on {0}'.format(hdl.switchName))
                  return None
        iteration+=1
        time.sleep(interval)
    #end of while
    testResult('fail','MTS buffer usage verification failed in duration of {0} seconds on {1}'\
                      .format(duration,hdl.switchName),log)
   
    #Retrives the messages with age > MAX_Q_AGE from mts buffer detail output
    detail_dict=getMtsBuffersDetailDict(hdl,log,arg2)
    if detail_dict:
         #Report all messages with age>MAX_Q_AGE
         for mod in detail_dict.keys():
              for key in detail_dict[mod].keys():
                  #reports only the messages > MAX_Q_AGE and exceeding MTS_Q_THRESHOLD
                  if (mod,key[0],key[2]) in self.failure_list:
                       log.error('There are {0} messages with age>{4}ms in (node,src-sap, dst-sap,opc): {1}\
                       on module {2} of {3}'.format(detail_dict[mod][key],key,mod,hdl.switchName,MAX_Q_AGE))
                       self.failure_details.append(detail_dict[mod][key])

    if self.failure_details:
        self.result='fail'
    else:
        self.result='pass'
    #return None

class verifyBgpNeighbor():

  def __init__(self,hdl, log, *args, **bgp_dict):
    self.result='pass'

    # Sample Usage:
    # verifyBgpNeighbor(hdl,log)
    # verifyBgpNeighbor(hdl,log, '-vrf default')
    # verifyBgpNeighbor(hdl,log, neighbor_list)
    # verifyBgpNeighbor(hdl,log, **neighbor_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbors']='-type str'
    arggrammar['as_no']='-type list'
    arggrammar['state']='-type str -default Established'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    as_no = parse_output.as_no
    # Get the actual output from switch
    if parse_output.vrf:
        out_bgp_dict = getIpv4BgpNeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_bgp_dict = getIpv4BgpNeighborDict(hdl,log)
    if parse_output.neighbors:
        neighbors=re.findall('('+rex.IPv4_ADDR+')',parse_output.neighbors)
    else:
        neighbors = []
        
    # All verification steps as below
    if bgp_dict:
        # The values from this dictionary will be verified against the values from get proc
        for nei in bgp_dict.keys():
            if (nei not in out_bgp_dict.keys()):
                testResult('fail','No Info for BGP Neighbor:{0} on {1}'.\
                                format(nei,out_bgp_dict[nei]['localhost']),log)
                continue
            # Check Expected keys are in output keys , return fail if it's not,
            # check following lines otherwise
            for key in bgp_dict[nei].keys():
                if key not in out_bgp_dict[nei].keys():
                    testResult('fail','No Info for key:({0}) for BGP Neighbor {1}'.\
                                    format(key,nei),log)
                    continue
                #To Do exact match
                if (bgp_dict[nei][key] == out_bgp_dict[nei][key]):
                    testResult('pass','BGP Neighbor:{0} has value {1} for {2}'.\
                                    format(nei,out_bgp_dict[nei][key],key),log)
                else:
                    testResult('fail','BGP Neighbor:{0} has value {1} for {2}'.\
                                    format(nei,out_bgp_dict[nei][key],key),log)
    if (neighbors) and (as_no):
        for nei in neighbors:
            if (out_bgp_dict[nei]['as'] in parse_output.as_no):
                if (out_bgp_dict[nei]['state'] == '{0}'.format(parse_output.state)):
                    #testResult('pass','BGP Neighbor:{0} with localhost {1} with State as {2}'.\
                    #format(nei,out_bgp_dict[nei]['localhost'],parse_output.state),log)
                    log.info('BGP Neighbor:{0} with localhost {1} with State as {2}'.\
                        format(nei,out_bgp_dict[nei]['localhost']))
                else:
                    testResult('fail','BGP Neighbor:{0} with local host {1} NOT in State as {2}'.\
                    format(nei,out_bgp_dict[nei]['localhost'],parse_output.state),log)
            else:
                print (' AS {0} not in the given list'.format(as_no))
                continue
    if neighbors:
        # Neighbors will be tested in this section to make sure they are in Established state
        for nei in neighbors:
            if (nei not in  out_bgp_dict.keys()):
                # If this is not in output then fail cases
                testResult('fail','BGP Neighbor:{0} NOT in BGP neighbor list'.format(nei),log)
            else:
                # Go through list of all neighbors and make sure it's in Established state
                if (out_bgp_dict[nei]['state'] == '{0}'.format(parse_output.state)):
                    #testResult('pass','BGP Neighbor:{0} with localhost {1} with State {2}'.\
                    #format(nei,out_bgp_dict[nei]['localhost'],parse_output.state),log)
                    log.info('BGP Neighbor:{0} with localhost {1} with State {2}'.\
                       format(nei,out_bgp_dict[nei]['localhost'],parse_output.state))
                else:
                    testResult('fail','BGP Neighbor {0} NOT in {1} State on {2}'.\
                    format(nei,parse_output.state,hdl.switchName),log)
     
    if as_no:
        for nei in out_bgp_dict.keys():
            if (out_bgp_dict[nei]['as'] in parse_output.as_no):
                if (out_bgp_dict[nei]['state'] == '{0}'.format(parse_output.state)):
                    #testResult('pass','BGP Neighbor:{0} with localhost {1} with State as {2}'.\
                    #format(nei,out_bgp_dict[nei]['localhost'],parse_output.state),log)
                    log.info('BGP Neighbor:{0} with localhost {1} with State as {2}'.\
                       format(nei,out_bgp_dict[nei]['localhost'],parse_output.state))
                else:
                    testResult('fail','BGP Neighbor:{0} with local host {1} NOT in State as {2}'.\
                    format(nei,out_bgp_dict[nei]['localhost'],parse_output.state),log)
            else:
                print (' neighbor is {0} and dict is {1}'.format(nei,out_bgp_dict))
                continue
                
    if (not neighbors) and (not as_no) and (not bgp_dict):
        # Verify all neighbors are in Established State, verification assumes right state is Established
        for nei in out_bgp_dict.keys():
            if (out_bgp_dict[nei]['state'] == '{0}'.format(parse_output.state)):
                #testResult('pass','BGP Neighbor:{0} with localhost {1} with State as {2}'.\
                #                format(nei,out_bgp_dict[nei]['localhost'],parse_output.state),log)
                log.info('BGP Neighbor:{0} with localhost {1} with State as {2}'.\
                                format(nei,out_bgp_dict[nei]['localhost'],parse_output.state))

            else:
                testResult('fail','BGP Neighbor:{0} with local host {1} NOT in State as {2}'.\
                                format(nei,out_bgp_dict[nei]['localhost'],parse_output.state),log)

 

class verifyBgpIpv6Neighbor():

  def __init__(self,hdl, log, *args, **bgpv6_dict):
    self.result='pass'

    # Sample Usage:
    # verifyBgpIpv6Neighbor(hdl,log)
    # verifyBgpIpv6Neighbor(hdl,log, '-vrf default')
    # verifyBgpIpv6Neighbor(hdl,log, neighbor_list)
    # verifyBgpIpv6Neighbor(hdl,log, **neighbor_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbors']='-type str'
    arggrammar['state']='-type str -default Established'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_bgpv6_dict = getIpv6BgpNeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_bgpv6_dict = getIpv6BgpNeighborDict(hdl,log)
    if parse_output.neighbors:
        neighbors=re.findall('('+rex.IPv6_ADDR+')',parse_output.neighbors)
    else:
        neighbors = []
    # All verification steps as below
    if bgpv6_dict:
        # The values from this dictionary will be verified against the values from get proc
        for nei in bgpv6_dict.keys():
            if (nei not in out_bgpv6_dict.keys()):
                testResult('fail','No Info for BGP Neighbor:{0} for {1}'.\
                                format(nei,out_bgpv6_dict[nei]['localhost']),log)
                continue
            # Check Expected keys are in output keys , return fail if it's not,
            # check following lines otherwise
            for key in bgpv6_dict[nei].keys():
                if key not in out_bgpv6_dict[nei].keys():
                    testResult('fail','No Info for key:({0}) for BGP Neighbor {1}'.\
                                    format(key,nei),log)
                    continue
                #To Do exact match
                if (bgpv6_dict[nei][key] == out_bgpv6_dict[nei][key]):
                    testResult('pass','BGP Neighbor:{0} has value {1} for {2}'.\
                                    format(nei,out_bgpv6_dict[nei][key],key),log)
                else:
                    testResult('fail','BGP Neighbor:{0} has value {1} for {2}'.\
                                    format(nei,out_bgpv6_dict[nei][key],key),log)
    if neighbors:
        # Neighbors will be tested in this section to make sure they are in Established state
        for nei in neighbors:
            if (nei not in  out_bgpv6_dict.keys()):
                # If this is not in output then fail cases
                testResult('fail','BGP Neighbor:{0} NOT in BGP neighbor list'.format(nei),log)
            else:
                # Go through list of all neighbors and make sure it's in Established state
                if (out_bgpv6_dict[nei]['state'] == '{0}'.format(parse_output.state)):
                    log.info('BGP Neighbor:{0} with localhost {1} with State {2}'.\
                       format(nei,out_bgpv6_dict[nei]['localhost'],parse_output.state))
                else:
                    testResult('fail','BGP Neighbor {0} NOT in {1} State on {2}'.\
                       format(nei,parse_output.state,hdl.switchName),log)

    if (not neighbors) and (not bgpv6_dict):
        # Verify all neighbors are in Established State, verification assumes right state is Established
        for nei in out_bgpv6_dict.keys():
            if (out_bgpv6_dict[nei]['state'] == 'Established'):
                testResult('pass','BGP Neighbor:{0} in Established State for {1}'.\
                                format(nei,out_bgpv6_dict[nei]['localhost']),log)
            else:
                testResult('fail','BGP Neighbor:{0} NOT in Established State for {1}'.\
                                format(nei,out_bgpv6_dict[nei]['localhost']),log)




class verifySpanningTreeStatesTotalDict():
  "  Added by sandesub\
  Description: Verifies the total count of blocking/listening/learning/forwarding/STP active ports across all VLANs using the output of show spanning-tree summary totals command on the switch\
  Sample Usage:\
  verifySpanningTreeStatesTotalDict(hdl,log,**stp_states_count_dict) - verification across all VLANs\
  test_dict = {'Name':'200','Blocking':'0', 'Listening':'0', 'Learning':'0', 'Forwarding':'202', 'STP Active':'202'}\
print verify_lib.verifySpanningTreeStatesTotalDict(hdl, log, **test_dict)"
  def __init__(self,hdl,log, **stp_states_count_dict):
    self.result='pass'
    output_stp_states_count_dict = getSpanningTreeStatesTotalDict(hdl,log)
    if stp_states_count_dict:
        if (compareVars(stp_states_count_dict,output_stp_states_count_dict,log) == 'pass'):
                testResult('pass','All state counts are correct. Expected dict: {0} Actual dict: {1}'.format(stp_states_count_dict,output_stp_states_count_dict),log)
        else:
                testResult('fail','State counts are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(stp_states_count_dict,output_stp_states_count_dict),log)
                self.result='fail'



class verifySpanningTreeTCNDict():
  "  Added by sandesub\
  Description: verify number of TCNs per vlan\
  Sample Usage:\
  test_dict = {'1':{'tcns':'7'}}\
  print verify_lib.verifySpanningTreeTCNDict(hdl,log)\
print verify_lib.verifySpanningTreeTCNDict(hdl,log,**dict)"
  def __init__(self,hdl,log,**stp_tcn_dict):
        self.result='pass'
        output_dict = getSpanningTreeTCNDict(hdl,log)
        if stp_tcn_dict:
                if (compareVars(stp_tcn_dict,output_dict,log)  == 'pass'):
                        testResult('pass','TCN count matches',log)
                else:
                        testResult('fail','TCN count does not match. Expected dict: {0} Actual dict: {1}'.format(stp_tcn_dict,output_dict),log)
                        self.result='fail'
        else:
                        testResult('fail', 'Mandatory DICT not passed',log)
                        self.result='fail'




class verifyHsrpHardwareConsistency():
  "  verifyHsrpHardwareConsistency - Method to verify the HSRP mac in hardware & software are consistent\
  \
  mandatory args: hdl, log\
  \
  Optional args: hsrplist\
  Usage Examples: verifyHsrpHardwareConsistency(hdl, log) - Verifies all HSRP instances on all LCs that has member ports\
  verifyHsrpHardwareConsistency(hdl, log, '-hsrplist 1,3') - Verifies HSRP groups 1,3.\
  If same VRRP group is configured under multiple interfaces, this will validate against all\
  the interfaces where same HSRP instance is configured\
  verifyHsrpHardwareConsistency(hdl, log, '-hsrplist Vlan100 1, Vlan2 2') - Verifies HSRP instances Vlan100,1\
  and Vlan2,2"
  def __init__(self,hdl, log, *args):
    self.result='pass'
        
    arggrammar={}
    arggrammar['hsrplist']=''
    arggrammar['hsrptuple']=''
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,'namespace')
    
    #Get Hsrp dict from DUT
    showhsrpdict=getHsrpDict(hdl,log)
        
    hsrpkeys=[]
    
    #If hsrplist is given get the key list for vrrp dict
    if parse_output.hsrplist:
            hsrpkeys=getKeys(parse_output.hsrplist,showhsrpdict.keys())
    #If hsrp tuple is given convert to list of tuples
    elif parse_output.hsrptuple:
        hsrpkeys1=strtolistoftuple(parse_output.hsrptuple)
        for hsrp in hsrpkeys1:
            hsrpl=list(hsrp)
            hsrpl[0]=normalizeInterfaceName(log, hsrpl[0])
            hsrp=tuple(hsrpl)
            hsrpkeys.append(hsrp)
    else:
        hsrpkeys=showhsrpdict.keys()
    
    for hsrp in hsrpkeys:
      # If hsrptuple values passed are not on Dut
        if hsrp not in showhsrpdict.keys():
            testResult('fail', 'hsrp group {0} on {1} is not configured on {2}'.format(hsrp[1], hsrp[0], hdl.switchName), log)
            continue

        #For each hsrp instance, get the hsrp virtual mac from dict
        hsrp_mac=showhsrpdict[hsrp]['Virtual mac address']
        
        hsrp_interface=hsrp[0]
        if re.search('vlan',hsrp_interface, re.I):
            hsrp_vlan=hsrp[0].lstrip('Vlan')
            lclist=getLcListFromInterface(hdl, log, '-vlan {0}'.format(hsrp_vlan))
            int_type='vlan'
        elif re.search('eth',hsrp_interface, re.I):
            hsrp_int=hsrp[0]
            lclist=getLcListFromInterface(hdl, log, '-interface {0}'.format(hsrp_interface))
            int_type='eth'
        elif re.search('po', vrrp_interface, re.I):
            hsrp_int=hsrp[0]
            lclist=getLcListFromInterface(hdl, log, '-port_channel {0}'.format(hsrp_interface))
            int_type='po'
        else:
            log.info('Invalid hsrp interface -{0}'.format(hsrp_interface))


        #For hsrp in active state, for vmac, verify G bit and port as sup-eth1
        if showhsrpdict[hsrp]['state']=='Active':

            if int_type=='vlan':
                mac_dict=getMacAddressTableDict(hdl, log, '-static -address {0} -vlan {1}'.format(hsrp_mac, hsrp_vlan))
            elif (int_type=='eth' or int_type=='po'):
                mac_dict=getMacAddressTableDict(hdl, log, '-static -address {0} -interface {1}'.format(hsrp_mac, hsrp_int))

            if mac_dict[(hsrp_mac,hsrp_vlan)]['Flag']=='G' and mac_dict[(hsrp_mac,hsrp_vlan)]['Port']=='sup-eth1(R)':
                #After verify successful on sup, check on each LC
                #TODO - need to change this based on EOR hardware commands
                for lc in lclist:
                    hwmacdict=getHardwareMacTableDict(hdl,log,'-module {0} -flag static -address {1} -vlan {2}'.format(lc, hsrp_mac, hsrp_vlan))
                    for key in hwmacdict.keys():
                        if hwmacdict[key]['gm']=='1' and hwmacdict[key]['mac_type']=='1' :
                            testResult('Pass','Hardware mac entry for hsrp group {0} on {1} verified on \
                                module {2} and fe {3}'.format(hsrp[1], hsrp[0],lc,key[0]), log)
                        else:
                            testResult('Fail','Hardware mac entry for hsrp group {0} on {1} not verified on \
                                module {2} and fe {3}'.format(hsrp[1], hsrp[0],lc,key[0]), log)
            else:
                testResult('Fail','Hsrp group {0} {1} mac verification on Sup failed'.format(hsrp[1], hsrp[1]), log)
                
        
        elif showhsrpdict[hsrp]['state']=='Standby':
            if int_type=='vlan':
                mac_dict=getMacAddressTableDict(hdl, log, '-static -address {0} -vlan {1}'.format(hsrp_mac, hsrp_vlan))
            elif (int_type=='eth' or int_type=='po'):
                mac_dict=getMacAddressTableDict(hdl, log, '-static -address {0} -interface {1}'.format(hsrp_mac, hsrp_int))

            # Virtual mac verification on Sup for Hsrp groups in standby mode
            if mac_dict[(hsrp_mac,hsrp_vlan)]['Flag']=='G':
                 # Virtual mac verification on each LC
                 for lc in lclist:
                    hwmacdict=getHardwareMacTableDict(hdl,log,'-module {0} -flag static -address {1} -vlan {2}'.format(lc, hsrp_mac, hsrp_vlan))
                    for key in hwmacdict.keys():
                        if hwmacdict[key]['gm']=='1' and hwmacdict[key]['mac_type']=='1' :
                            testResult('Pass','Hardware mac entry for hsrp group {0} on {1} verified on \
                                module {2} and fe {3}'.format(hsrp[1], hsrp[0],lc,key[0]), log)
                        else:
                            testResult('Fail','Hardware mac entry for hsrp group {0} on {1} not verified on \
                                module {2} and fe {3}'.format(hsrp[1], hsrp[0],lc,key[0]), log)
        else:
            testResult('Fail','Hsrp group {0} on {1} mac verification on Sup failed'.format(hsrp[1], hsrp[0]), log)
 
class verifyIgmpSnoopingOmfRoute():
  '''  verifyIgmpSnoopingOMFRoute - Method to verify IGMP snooping OMF Route
  mandatory args: hdl, log, value=inDict
  Optional args:
  
  Usage Examples: verifyIgmpSnoopingOmfRoute(hdl, log,value=inDict) - Verify igmp snooping Route 
  based on the given inDict
  e.g. inDict:
  OMF route (*,*) with oif list of eth3/47 and eth3/46 for Vlans 10,11
  {'10,11':['Eth3/47', 'Eth3/46']}
  '''
  def __init__(self,hdl, log, *args, **inDict):
    arggrammar={}
    arggrammar['svi_querier']='-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log)
    
    self.result='pass'

    if not inDict:
        testResult ('fail','verifyIgmpSnoopingOmfRoute: argument - inDict is missing',log)
        self.result='fail'
        return None
    else:
        inDict=inDict['value']

    outDict=getIgmpSnoopingGroupsDict(hdl,log,'-omf_only True')
    omf_dict={}
    for vlans in inDict.keys():
        for vlan in strtoexpandedlist(vlans):
            if not ns.svi_querier: 
                omf_dict[vlan,'*','*','-','R']=strtoexpandedlist(normalizeInterfaceName(log,inDict[vlans]))
            else:
                intf_list=strtoexpandedlist(normalizeInterfaceName(log,inDict[vlans]))
                intf_list.append(normalizeInterfaceName(log,'vlan'+vlan))
                omf_dict[vlan,'*','*','-','R']=intf_list
    if not findDict(log,omf_dict,outDict):
        self.result='fail'
     
    return None


class verifyIgmpSnoopingGroups():
  "  verifyIgmpSnoopingGroups - Method to verify IGMP snooping groups\
  \
  mandatory args: hdl, log, value=inDict\
  Optional args:\
  \
  Usage Examples: verifyIgmpSnoopingGroups(hdl, log,value=inDict) - Verify igmp snooping groups\
  based on the given inDict\
  e.g. inDict:\
  (*,225.0.0.0) of igmp version 'v2' and dynamic entries with oif list of eth3/47 and eth3/46 for Vlans 10,11\
  {('10,11','*','225.0.0.0','v2','D'):['Eth3/47', 'Eth3/46']}\
  (*,225.0.0.x) of igmp version 'v2' and dynamic entries with x=1-10 and oif list of eth3/46 and eth3/47 for vlan10 and vlan11\
  {('10,11','*','225.0.0.1 225.0.0.10 1','v2','D'):['Eth3/47', 'Eth3/46']}\
  (10.0.0.x,225.0.0.y) with x=1-10 and y=1-10 of version 'v3' and static entries with oif list of eth3/46 and eth3/47 for vlan 8 and range 10 to 20\
  {('8,10-20','10.0.0.1 10.0.0.10 1','225.0.0.1 225.0.0.10 1','v3','S'):['Eth3/47', 'Eth3/46']}"
  def __init__(self,hdl, log, **inDict):
    self.result='pass'

    if not inDict:
        testResult ('fail','verifyIgmpSnoopingGroups: argument - inDict is missing',log)
        self.result='fail'
        return None
    else:
        inDict=inDict['value']

    outDict=getIgmpSnoopingGroupsDict(hdl,log)

    #A Dict is created by replicating vlan_list,source_list and group_list from inDict
    snoopDict={}
    for key in inDict.keys():
        if len(key)<3:
            testResult('fail','verifyIgmpSnoopingGroups: invalid argument inDict',log)
            self.result='fail'
            return None
        vlan_list=key[0]
        vlan_list=strtoexpandedlist(vlan_list)
        source_list=retIpAddressList(key[1])
        group_list=retIpAddressList(key[2])
        if len(key)>=4:
             version=key[3]
        else:
             version='v2'
        if len(key)==5:
             type=key[4]
        else:
             type='D'
        oif=inDict[key]
        for vlan in vlan_list:
            for src in source_list:
                for grp in group_list:
                    tmp={(vlan,src,grp,version,type):normalizeInterfaceName(log,oif)}
                    snoopDict.update(tmp)
    if not findDict(log,snoopDict,outDict):
        self.result='fail'

    return None
 
##############


class verifyMldGroupCount ():

  def __init__(self,hdl, log, *args):
    self.result='pass'
    

    # Sample Usage
    # verifyMldGroupCount(hdl,log,'-count 1 -flag sgcount')
    # verifyMldGroupCount(hdl,log,'-count 2 -flag stargcount')
    # verifyMldGroupCount(hdl,log,'-count 100 -flag total -vrf all')
 
    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['count']='-type int -required True'
    arggrammar['flag']='-type str -choices ["stargcount","sgcount","total"] -default Total'
    arggrammar['verify_iteration']='-type int -default 1'
    arggrammar['interval']='-type int -default 15'

    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    verify_iteration=parse_output.verify_iteration
    interval=parse_output.interval
    count = parse_output.count
    flag = parse_output.flag.lower()
    options = '-flag ' + flag
    if parse_output.vrf:
        options += ' -vrf ' + parse_output.vrf
    if not loop_until("getMldGroupCount",(hdl,log,options),count,'-iteration {0} -interval {1}'.format(verify_iteration,interval)):
        testResult('fail','verifyMldGroupCount failed on {0}'.format(hdl.switchName),log)
    else:
        testResult('pass','verifyMldGroupCount passed on {0}'.format(hdl.switchName),log)

###################################################################################

class verifyPim6Neighbor ():

  def __init__(self,hdl, log, *args):
    self.result='pass'
     
    # Verifies neighbors are listed in the PIM6 neighbor table 

    # Sample Usage:
    # neighbors=[('fe80::200:42ff:fe96:4fc8','Eth3/48'),('fe80::200:42ff:fe96:4fc6','vlan10')]
    # verifyPim6Neighbor(hdl,log, '-vrf default -neighbors ' + listtostr(neighbors))
    # verifyPim6Neighbor(hdl,log, '-neighbors ' + listtostr(neighbors))
    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbors']='-type str -required True'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
    neighbors=parse_output.neighbors 
    neighbors=strtolistoftuple(neighbors)
    # Get the actual output from switch
    if parse_output.vrf:
        out_pim_dict = getPim6NeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_pim_dict = getPim6NeighborDict(hdl,log)

    # Get list of neighbors with normalized ipv6 address and interface name
    # And verify if key of (neighbor,interface) is found in out_dict
    result=True
    for nei in neighbors:
        ipv6_full=ipaddr.IPv6Address(nei[0]).exploded
        int=normalizeInterfaceName(log,nei[1])
        if ((ipv6_full,int) not in  out_pim_dict.keys()):
            # If this is not in output then fail cases
            testResult('fail','Neighbor:{0} NOT in PIM neighbor list'.format((ipv6_full,int)),log)
            result=False

    if result:
        testResult('pass','PIM6 neighbor verfication passes',log)

    return None

###############################################################

class verifyPim6Interface():

  def __init__(self,hdl, log, *args, **pim_dict):
    self.result='pass'

    # Sample Usage:

    # verifyPim6Interface(hdl,log, '-vrf default -interfaces ' + str(interfaces))
    # verifyPim6Interface(hdl,log, **pim_dict)

    # pim_dict is build as below
    # pim_dict = {}
    # pim_dict['Ethernet4/1'] = {}
    # pim_dict['Ethernet4/1']['IPv6_Address'] = 'fe80::da67:d9ff:fe0a:4bc3'
    # pim_dict['Ethernet4/1']['PIM6_DR_Address'] = 'fe80::da67:d9ff:fe0a:4bc3'
    # pim_dict['Ethernet4/1']['Neighbor_Count'] = '1'

    # verifyPim6Interface(hdl,log,**pim_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['interfaces']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_pim_dict = getPim6InterfaceDict(hdl,log,'-vrf ' + parse_output.vrf)
    else:
        out_pim_dict = getPim6InterfaceDict(hdl,log)
    if parse_output.interfaces:
        interfaces=re.findall('('+rex.INTERFACE_NAME+')',parse_output.interfaces)
    else:
        interfaces = []

    if (not interfaces) and (not pim_dict):
        # No useful info passed for verification, return fail to avoid user errors
        testResult('fail','No useful info passed for verifying PIM6 interface table',log)
        return None

    # All verification steps as below
    result=True
    if pim_dict:
        # The values from this dictionary will be verified against the values from get proc
        if (compareVars(pim_dict,out_pim_dict,log) != 'pass'):
            testResult('fail','Expected values for PIM6 interfaces not in PIM6 interface table',log)
            result=False
    if interfaces:
        # Interfaces will be tested in this section to make sure they are in the list
        for intf in interfaces:
            if (intf not in  out_pim_dict.keys()):
                # If this is not in output then fail cases
                testResult('fail','No info for Interface:{0} in PIM6 interface table'.format(intf),log)
                result=False

    if result:
        testResult("pass","PIM6 interface verification passes",log)

    return None

############################


class verifyMroute6Count ():

  def __init__(self,hdl,log, *args):
    self.result='pass'

    # Sample Usage
    # verifyMroute6Count (hdl,log, -count 5')
    # verifyMroute6Count (hdl,log, '-count 10 -flag sgcount -vrf default')
    # verifyMroute6Count (hdl,log, '-count 1 -flag sgcount')
    # Verifies mroute6 count against the given count

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['count']='-type str -required True'
    arggrammar['flag']='-type str -choices ["sgcount","stargcount","starg-pfxcount","total"] -default total'
    arggrammar['verify_iterations']='-type int -default 1'
    arggrammar['verify_interval']='-type int -default 15'

    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    count = parse_output.count
    flag = parse_output.flag.lower()
    options = ' '
    verify_iterations=parse_output.verify_iterations 
    verify_interval=parse_output.verify_interval

    if parse_output.vrf:
        options += ' -vrf ' + parse_output.vrf 

    verified=False
    for iteration in range(verify_iterations):
        # Get the mroute count
        mroute_dict = getMroute6CountDict(hdl,log,options)
        if (flag == 'total'):
            get_count = mroute_dict['Total']
        elif (flag == 'stargcount'):
            get_count = mroute_dict['(*,G)_routes']
        elif (flag == 'sgcount'):
            get_count = mroute_dict['(S,G)_routes']
        elif (flag == 'starg-pfxcount'):
            get_count = mroute_dict['(*,G-prefix)_routes']
        if (count != get_count):
            log.info('Iteration: {3} - Expected m6routes not present,Looking for:{0},found:{1},expected:{2}'.\
                            format(flag,get_count,count,iteration))
        else:
            verified=True
    
        if (verified or iteration==verify_iterations-1):
            break

        time.sleep(verify_interval)

    if verified:
        testResult('pass','verifyMroute6Count passed',log)
    else:
        testResult('fail','verifyMroute6Count failed',log)


class verifyVrrpHardwareConsistency():
  "  verifyVrrpHardwareConsistency - Method to verify the VRRP mac in hardware & software are consistent\
  \
  mandatory args: hdl, log\
  \
  Optional args: hsrplist or hsrptuple\
  Usage Examples:        verifyVrrpHardwareConsistency(hdl, log) - Verifies all HSRP instances on all LCs that has member ports\
                          verifyVrrpHardwareConsistency(hdl, log, '-vrrplist 9,11')\
                          verifyVrrpHardwareConsistency(hdl, log, '-vrrptuple (Vlan9,9),(Ethernet6/40,11)')\
  "
  def __init__(self,hdl, log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['vrrplist']=''
    arggrammar['vrrptuple']=''
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,'namespace')
    
    vrrpkeys=[]
    #Get vrrp dict from DUT
    showvrrpdict=getVrrpv2Dict(hdl,log)
    
    #If vrrplist is given get the key list for vrrp dict
    if parse_output.vrrplist:
            vrrpkeys=getKeys(parse_output.vrrplist,showvrrpdict.keys())
    #If vrrp tuple is given convert to list of tuples
    elif parse_output.vrrptuple:
        vrrpkeys1=strtolistoftuple(parse_output.vrrptuple)
        for vrrp in vrrpkeys1:
            vrrpl=list(vrrp)
            vrrpl[0]=normalizeInterfaceName(log, vrrpl[0])
            vrrp=tuple(vrrpl)
            vrrpkeys.append(vrrp)
    else:
        vrrpkeys=showvrrpdict.keys()
    
    print ('vrrpkeys is {0}'.format(vrrpkeys)) 
    for vrrp in vrrpkeys:
        # If vrrplist/vrrptuple values passed are not on Dut
        if vrrp not in showvrrpdict.keys():
            testResult('fail', 'vrrp group {0} on {1} is not configured on {2}'.format(vrrp[1], vrrp[0], hdl.switchName), log)
            continue

        #For each vrrp instance, get the vrrp virtual mac from dict
        vrrp_mac=showvrrpdict[vrrp]['Virtual_MAC_address']
        
        vrrp_interface=vrrp[0]
        if re.search('vlan',vrrp_interface, re.I):
            vrrp_vlan=vrrp[0].lstrip('Vlan')
            lclist=getLcListFromInterface(hdl, log, '-vlan {0}'.format(vrrp_vlan))
            int_type='vlan'
        elif re.search('eth',vrrp_interface, re.I):
            vrrp_int=vrrp[0]
            lclist=getLcListFromInterface(hdl, log, '-interface {0}'.format(vrrp_interface))
            int_type='eth'
        elif re.search('po', vrrp_interface, re.I):
            vrrp_int=vrrp[0]
            lclist=getLcListFromInterface(hdl, log, '-port_channel {0}'.format(vrrp_interface))
            int_type='po'
        else:
            log.info('Invalid vrrp interface -{0}'.format(vrrp_interface))
        
        #For vrrp in Master state, for vmac, verify G bit and port as sup-eth1
        if showvrrpdict[vrrp]['State']=='Master':
            if int_type=='vlan':
                mac_dict=getMacAddressTableDict(hdl, log, '-static -address {0} -vlan {1}'.format(vrrp_mac, vrrp_vlan))
            elif (int_type=='eth' or int_type=='po'):
                mac_dict=getMacAddressTableDict(hdl, log, '-static -address {0} -interface {1}'.format(vrrp_mac, vrrp_int))
        
            if (mac_dict[(vrrp_mac,vrrp_vlan)]['Flag']=='G' and mac_dict[(vrrp_mac,vrrp_vlan)]['Port']=='sup-eth1(R)'):
                
                #After verify successful on sup, check on each LC
                #TODO - need to change this based on EOR hardware commands
                for lc in lclist:
                    if int_type=='vlan':
                        hwmacdict=getHardwareMacTableDict(hdl,log,'-module {0} -flag static -address {1} -vlan {2}'.\
                                                                format(lc, vrrp_mac, vrrp_vlan))
                    elif (int_type=='eth' or int_type=='po'):
                        hwmacdict=getHardwareMacTableDict(hdl,log,'-module {0} -flag static -address {1} -intf {2}'.\
                                                                format(lc, vrrp_mac, vrrp_vlan))
                    
                    for key in hwmacdict.keys():
                        if hwmacdict[key]['gm']=='1' and hwmacdict[key]['mac_type']=='1' :
                            testResult('Pass','Hardware mac entry for vrrp group {0} on {1} verified on \
                                module {2} and fe {3}'.format(vrrp[1], vrrp[0],lc,key[0]), log)
                        else:
                            testResult('Fail','Hardware mac entry for vrrp group {0} on {1} not verified on \
                                module {2} and fe {3}'.format(vrrp[1], vrrp[0],lc,key[0]), log)
            else:
                testResult('Fail','vrrp group {0} {1} mac verification on Sup failed'.format(vrrp[1], vrrp[1]), log)
                
        #Virtual mac verification on Sup for vrrp groups in standby mode
        elif showvrrpdict[vrrp]['State']=='Backup':
            if int_type=='vlan':
                mac_dict=getMacAddressTableDict(hdl, log, '-static -address {0} -vlan {1}'.format(vrrp_mac, vrrp_vlan))
            elif (int_type=='eth' or int_type=='po'):
                mac_dict=getMacAddressTableDict(hdl, log, '-static -address {0} -interface {1}'.format(vrrp_mac, vrrp_int))
            
            if mac_dict[(vrrp_mac,vrrp_vlan)]['Flag']=='G':
                 # Virtual mac verification on each LC
                 for lc in lclist:
                    if int_type=='vlan':
                        hwmacdict=getHardwareMacTableDict(hdl,log,'-module {0} -flag static -address {1} -vlan {2}'.\
                                                format(lc, vrrp_mac, vrrp_vlan))
                    elif (int_type=='eth' or int_type=='po'):
                        hwmacdict=getHardwareMacTableDict(hdl,log,'-module {0} -flag static -address {1} -intf {2}'.\
                                                format(lc, vrrp_mac, vrrp_vlan))
    
                    for key in hwmacdict.keys():
                        if hwmacdict[key]['gm']=='1' and hwmacdict[key]['mac_type']=='1' :
                            testResult('Pass','Hardware mac entry for vrrp group {0} on {1} verified on \
                                module {2} and fe {3}'.format(vrrp[1], vrrp[0],lc,key[0]), log)
                        else:
                            testResult('Fail','Hardware mac entry for vrrp group {0} on {1} not verified on \
                                module {2} and fe {3}'.format(vrrp[1], vrrp[0],lc,key[0]), log)
            else:
                testResult('Fail','vrrp group {0} on {1} mac verification on Sup failed'.format(vrrp[1], vrrp[0]), log)
        else:
            testResult('Fail','vrrp group {0} on {1} is in state {2}'.format(vrrp[1], vrrp[0], showvrrpdict[vrrp]['State']), log)


###########################################

class verifyMroute6 ():

  def __init__(self,hdl,log, *args, **mroute_dict):
    self.result='pass'

    # Summary:
    # Source info and receiver info can be passed as individual value or in form
    # of increment (usefull for 100s of mroutes where many are indentical)
    # rpf_interface can be a single interface or a list of interfaces (in case of ECMP RPF paths
    # oif_list can be be a list of interfaces or a keyword 'ANY_VALID' which will pass verification 
    # as long as any valid oif interfaces exist
    # sx_info1 = '2001::1' or sx = '2001::1, 2001::100, 1'
    # the later value will expand to 100 sources while verifying
    # Same goes for rx, increment can be any, all possible values between 
    # start and end are considered for verification
    #
    # rx_info1 = 'ff03::1' 
    # mroute_dict[sx_info1,rx_info1]={}
    # mroute_dict[sx_info1,rx_info1]['rpf_interface']='Ethernet4/1'
    # mroute_dict[sx_info1,rx_info1]['oif_list']=['Ethernet4/1']
    # mroute_dict[sx_info1,rx_info1]['uptime']='1:1:1'

    # verifies <show ipv6 mroute> output, accpets values via dict strutcture
    # It does exact match for all parameters passed, rpf_interface can be passed as
    # a list and it passes as long as output has one of this rpf_interface
    # oif_list should always be passed as list (consistence with getMroute)

    # Sample Usage:
    # verifyMroute6 (hdl,log, value=mroute_dict)
    # verifyMroute6(hdl,log,'-vrf default', value=mroute_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the actual output from switch
    if parse_output.vrf:
        out_mroute_dict = getMroute6Dict(hdl,log,'-vrf ' + parse_output.vrf)
        pass
    else:
        out_mroute_dict = getMroute6Dict(hdl,log)
        pass
    if not mroute_dict:
        testResult ('fail','IPv6 mroute info not passed for verification',log)
        return None
    else:
        mroute_dict = mroute_dict['value']

    # Construct the expected output for verification
    exp_mroute_dict = {}
    for key in mroute_dict.keys():
        # This can be list
        if key[0]!='*':
            sources = retIpv6AddressList(key[0])
        else:
            sources = key[0].split()
        # this can be list
        groups =  retIpv6AddressList(key[1])
        for source in sources:
            for group in groups:
                exp_mroute_dict[source,group] = {}
                for next_key in mroute_dict[key].keys():
                    if next_key=='oif_list' or next_key=='rpf_interface':
                        exp_mroute_dict[source,group][next_key]=normalizeInterfaceName(log,mroute_dict[key][next_key])
                    else:
                        exp_mroute_dict[source,group][next_key] = mroute_dict[key][next_key]
            pass
        pass

    # Perform Actual verification 
    result=True
    for key in exp_mroute_dict.keys():
        if (key not in out_mroute_dict.keys()):
            testResult ('fail','No info for {0} in ipv6 mroute output from switch'.format(key),log)
            result=False
            continue
        for next_key in exp_mroute_dict[key].keys():
            if (next_key not in out_mroute_dict[key].keys()):
                testResult ('fail','No info for key:{0} in ipv6 mroute output for:{1}'.format(key,next_key),log)
                result=False
                continue
            elif (next_key == 'rpf_interface'):
                if type(exp_mroute_dict[key][next_key])==str and (out_mroute_dict[key][next_key]!=exp_mroute_dict[key][next_key]):
                    testResult ('fail','RPF interface not in output for {0}.expected:{1},found:{2}'.\
                                    format(next_key,exp_mroute_dict[key][next_key],out_mroute_dict[key][next_key]),log)
                    result=False
                elif type(exp_mroute_dict[key][next_key])==list and (out_mroute_dict[key][next_key] not in exp_mroute_dict[key][next_key]):
                    testResult ('fail','RPF interface not in output for {0}.expected:{1},found:{2}'.\
                                    format(next_key,exp_mroute_dict[key][next_key],out_mroute_dict[key][next_key]),log)
                    result=False
            elif (next_key == 'oif_list'):
                if exp_mroute_dict[key][next_key]=='ANY_VALID':
                    if not len(out_mroute_dict[key][next_key]):
                        testResult ('fail','Incorrect match for key:{0} for {1}.expected:{2},found:{3}'.\
                                        format(key,next_key,exp_mroute_dict[key][next_key],\
                                                   out_mroute_dict[key][next_key]),log)
                        result=False
                elif (set(exp_mroute_dict[key][next_key]) != set(out_mroute_dict[key][next_key])):
                    testResult ('fail','Incorrect match for key:{0} for {1}.expected:{2},found:{3}'.\
                                    format(key,next_key,exp_mroute_dict[key][next_key],\
                                               out_mroute_dict[key][next_key]),log)
                    result=False
            elif (exp_mroute_dict[key][next_key] != out_mroute_dict[key][next_key]):
                    testResult ('fail','Incorrect match for key:{0} for {1}.expected:{2},found:{3}'.\
                                    format(key,next_key,exp_mroute_dict[key][next_key],\
                                               out_mroute_dict[key][next_key]),log)
                    result=False

    #if result:
         #testResult('pass','IPv6 mroute verification passes',log)

    return None   



class verifyInterfaceStatus():
  "  To verify all or given set of interfaces are in given status\
  Usage: verifyInterfaceStatus(hdl,log,'-status up')\
verifyInterfacesAreUp(hdl,log,'status up -interfaces Eth3/13-20')"
  def __init__(self,hdl,log,*args):
   self.result='pass'

   arggrammar={}
   arggrammar['interfaces']='-type str -default all'
   arggrammar['iteration']='-type int -default 1'
   arggrammar['interval']='-type int -default 30'
   arggrammar['status']='-type str -choices ["up","down","err-disabled","err-vlans","inactive"] -default "up"'

   ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
   ns.status=ns.status.strip("'")
   ns.status=ns.status.strip('"')

   if ns.interfaces == "all":
       interfaces=getInterfaceList(hdl,log)
       for iteration in range(ns.iteration):
           result=True
           if ns.status in ['up','down']:
               intdict=getInterfaceBriefDict(hdl,log)
               intstatusdict={}
               for interface in intdict:
                   interface=normalizeInterfaceName(log,interface)
                   if intdict[interface]['Status'] == ns.status:
                       intstatusdict[interface]=intdict[interface]
           else:
               intstatusdict=getInterfaceStatusDict(hdl,log, "-"+ns.status)
           if not len(intstatusdict.keys()):
               log.info('Iteration {0} No interfaces in {1} state'.format(iteration+1,ns.status))
               result=False
           else:
               for interface in interfaces:
                   interface=normalizeInterfaceName(log,interface)
                   if interface not in intstatusdict.keys(): 
                        log.info('Iteration {0} interface {1} not in {2} state'.format(iteration+1,interface,ns.status))
                        result=False
           if result or iteration == ns.iteration-1:
               break
           else:
               log.info("Sleeping for {0} seconds for next iteration".format(ns.interval))
               time.sleep(ns.interval)
       if result:
           testResult('pass','All interfaces in {0} state'.format(ns.status),log) 
       else:
           testResult('fail','Some or all interfaces not in {0} state'.format(ns.status),log) 
   else:
       interfaces=listtostr(strtoexpandedlist(ns.interfaces))
       for iteration in range(ns.iteration):
           result=True
           if ns.status in ['up','down']:
               intdict=getInterfaceBriefDict(hdl,log,'-interface {0}'.format(interfaces))
               intstatusdict={}
               for interface in intdict:
                   interface=normalizeInterfaceName(log,interface)
                   if intdict[interface]['Status'] == ns.status:
                       intstatusdict[interface]=intdict[interface]
           else:
               intstatusdict=getInterfaceStatusDict(hdl,log,'-interface {0} -{1}'.format(interfaces,ns.status))
           if not len(intstatusdict.keys()):
               log.info('Iteration {0} No interfaces in {1} state'.format(iteration+1,ns.status))
               result=False
           else:
               for interface in strtoexpandedlist(interfaces):
                   if normalizeInterfaceName(log,interface) not in intstatusdict.keys(): 
                        log.info('Iteration {0} interface {1} not in {2} state'.format(iteration+1,interface,ns.status))
                        result=False
           if result or iteration == ns.iteration-1:
               break
           else:
               log.info("Sleeping for {0} seconds for next iteration".format(ns.interval))
               time.sleep(ns.interval)
       if result:
           log.info('Interfaces {0} in {1} state'.format(interfaces,ns.status))
       else:
           testResult('fail','Some or all of the {0} not in {1} state'.format(interfaces,ns.status),log) 



class verifyIPv4InterfaceStatus():
    '''  To verify given set of Ipv4 interfaces are in given status 
    Usage: verifyIpv4InterfaceStatus(hdl,log,'-interface Eth3/1,Eth3/2 -status protocol-up,link-up,admin-up')
     '''
    def __init__(self,hdl,log,*args):
        self.result='pass'
        
        arggrammar={}
        arggrammar['interfaces']='-type str -required True'
        arggrammar['iteration']='-type int -default 1'
        arggrammar['interval']='-type int -default 30'
        arggrammar['status']='-type str -subset ["protocol-down","link-down","link-up","protocol-up","admin-down","admin-up"] -default "protocol-up,link-up,admin-up"'
        arggrammar['vrf']='-type str -default default'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        status_list=strToList(ns.status)
        interface_list=strToList(ns.interfaces)
        int_list=[]
        for int in interface_list:
            int_list.append(normalizeInterfaceName(log,int))

        for loop in range(ns.iteration):
            ip_int_dict=getIpv4InterfaceBriefDict(hdl, log, '-vrf {0}'.format(ns.vrf))
            loopuntil_result='pass'
            for interface in int_list:
                if interface not in ip_int_dict.keys():
                    testResult('fail','Interface {0} not in Ipv4 interface brief dict'.format(interface), log)
                    loopuntil_result='fail'
                    continue
                else:
                    for status in status_list:
                        if not re.search(status, ip_int_dict[interface]['Interface Status'], re.I):
                            loopuntil_result='fail'
            if loopuntil_result=='pass':
                break
            if loop==ns.iteration-1:
                self.result='fail'
                testResult('fail','Interfaces {0} not in expected state {1}'.format(listtostr(int_list), listtostr(status_list)),log)
            else:
                time.sleep(ns.interval)
         
        if self.result=='pass':
            testResult('pass','Interfaces {0} have expected status {1}'.format(listtostr(int_list), listtostr(status_list)), log)
        else:
            testResult('fail','Interfaces {0} are not in expected status {1}'.format(listtostr(int_list), listtostr(status_list)), log) 




class verifyOspfInterfaceStatus():
    '''  To verify given set of Ospf interfaces are in given status 
    Usage: verifyOspfInterfaceStatus(hdl,log,'-interface Eth3/1,vlan101-104')
        verifyOspfInterfaceStatus(hdl,log,'-interface Eth3/1,vlan101-104 -status down')
     '''
    def __init__(self,hdl,log,*args):
        self.result='pass'
        
        arggrammar={}
        arggrammar['interfaces']='-type str -required True'
        arggrammar['vrf']='-type str'
        arggrammar['iteration']='-type int -default 1'
        arggrammar['interval']='-type int -default 30'
        arggrammar['status']='-type str -choices ["up","down"] -default up'
        
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface_list=strtoexpandedlist(ns.interfaces)
        int_list=[]
        for int in interface_list:
            int_list.append(normalizeInterfaceName(log,int))
        for loop in range(ns.iteration):
            if ns.vrf:
                ospf_int_dict=getIpOspfInterfaceBriefDict(hdl, log, '-vrf {0}'.format(ns.vrf))
            else:
                ospf_int_dict=getIpOspfInterfaceBriefDict(hdl, log)
            loopuntil_result='pass'
            for int in int_list:
                if int not in ospf_int_dict.keys():
                    log.info('Ospf interface {0} not in show ip Ospf interface brief output on {1}'.format(int, hdl.switchName))
                    loopuntil_result='fail'
                    continue
                elif ospf_int_dict[int]['status']!=ns.status:
                    log.info('Ospf interface {0} in status {1} - expected status {2} on {3}'.format(int,ospf_int_dict[int]['status'], ns.status, hdl.switchName))
                    loopuntil_result='fail'
                else:
                    log.info('Ospf interface {0} in expected status {1} on {2}'.format(int,ospf_int_dict[int]['status'], hdl.switchName))
            if loopuntil_result=='pass':
                break
            if loop==ns.iteration-1:
                self.result='fail'
                testResult('fail','Ospf interfaces {0} not in expected state {1} on {2}'.format(listtostr(int_list), ns.status, hdl.switchName),log)
            else:
                time.sleep(ns.interval)
         
        if self.result=='pass':
            testResult('pass','Ospf interfaces {0} are in expected status {1} on {2}'.format(listtostr(int_list), ns.status, hdl.switchName), log)
        else:
            testResult('fail','Ospf interfaces {0} are not in expected status {1} on {2}'.format(listtostr(int_list), ns.status, hdl.switchName), log) 


class verifyOspfv3InterfaceStatus():
    '''  To verify given set of Ospf interfaces are in given status 
    Usage: verifyOspfInterfaceStatus(hdl,log,'-interface Eth3/1,vlan101-104')
        verifyOspfInterfaceStatus(hdl,log,'-interface Eth3/1,vlan101-104 -status down')
     '''
    def __init__(self,hdl,log,*args):
        self.result='pass'
        
        arggrammar={}
        arggrammar['interfaces']='-type str -required True'
        arggrammar['vrf']='-type str'
        arggrammar['iteration']='-type int -default 1'
        arggrammar['interval']='-type int -default 30'
        arggrammar['status']='-type str -choices ["up","down"] -default up'
        
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface_list=strtoexpandedlist(ns.interfaces)
        int_list=[]
        for int in interface_list:
            int_list.append(normalizeInterfaceName(log,int))
        for loop in range(ns.iteration):
            if ns.vrf:
                ospf_int_dict=etIpOspfv3InterfaceBriefDict(hdl, log, '-vrf {0}'.format(ns.vrf))
            else:
                ospf_int_dict=getOspfv3InterfaceDict(hdl, log)
            loopuntil_result='pass'
            for int in int_list:
                if int not in ospf_int_dict.keys():
                    log.info('Ospfv3 interface {0} not in show ip Ospf interface brief output on {1}'.format(int, hdl.switchName))
                    loopuntil_result='fail'
                    continue
                elif ospf_int_dict[int]['Status']!=ns.status:
                    log.info('Ospfv3 interface {0} in status {1} - expected status {2} on {3}'.format(int,ospf_int_dict[int]['Status'], ns.status, hdl.switchName))
                    loopuntil_result='fail'
                else:
                    log.info('Ospfv3 interface {0} in expected status {1} on {2}'.format(int,ospf_int_dict[int]['Status'], hdl.switchName))
            if loopuntil_result=='pass':
                break
            if loop==ns.iteration-1:
                self.result='fail'
                testResult('fail','Ospfv3 interfaces {0} not in expected state {1} on {2}'.format(listtostr(int_list), ns.status, hdl.switchName),log)
            else:
                time.sleep(ns.interval)
         
        if self.result=='pass':
            testResult('pass','Ospfv3 interfaces {0} are in expected status {1} on {2}'.format(listtostr(int_list), ns.status, hdl.switchName), log)
        else:
            testResult('fail','Ospfv3 interfaces {0} are not in expected status {1} on {2}'.format(listtostr(int_list), ns.status, hdl.switchName), log) 




class verifyIpRoute():
    '''  To verify given Ipv4 route is on the dut 
    Usage: 
    verifyIpRoute(hdl1, log, '-dest_ip 30.30.30.0 -mask 24 -type ospf -interface eth4/5 -next_hop 10.10.10.2')
    verifyIpRoute(hdl1, log, '-dest_ip 30.30.30.0 -mask 24 -type ospf')
    verifyIpRoute(hdl1, log, '-dest_ip 1.1.0.0 -mask 16 -next_hop 1.1.1.2 -type direct -vrf test')
    
     '''
    def __init__(self,hdl,log,*args):
        self.result='pass'
        
        arggrammar={}
        arggrammar['dest_ip']='-type str -required True'
        arggrammar['mask']='-type str -required True'
        arggrammar['next_hop']='-type str'
        arggrammar['interface']='-type str'
        arggrammar['type']='-type str'   
        arggrammar['vrf']='-type str'
        arggrammar['iteration']='-type int -default 1'
        arggrammar['interval']='-type int -default 30'
   
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)     

        for loop in range(ns.iteration):
            if ns.vrf:
                route_dict=getRouteDict(hdl, log, '-vrf {0}'.format(ns.vrf))
            else:
                route_dict=getRouteDict(hdl, log)
            loopuntil_result='pass'
            if (ns.dest_ip, ns.mask) not in route_dict.keys():
               log.info('Ip destination {0}/{1} not in {2} route table'.format(ns.dest_ip, ns.mask, hdl.switchName))
               loopuntil_result='fail'
            else:
                if ns.next_hop:
                    if ns.next_hop not in route_dict[(ns.dest_ip, ns.mask)]['next_hop'].keys():
                        log.info('Ip destination {0}/{1} doesnt have nexthop {2} in {3} route table'.\
                                   format(ns.dest_ip, ns.mask, ns.next_hop, hdl.switchName))
                        loopuntil_result='fail'
                        
                if ns.type:
                    if ns.next_hop:
                        if ns.next_hop not in route_dict[(ns.dest_ip, ns.mask)]['next_hop'].keys():
                            loopuntil_result='fail'
                        
                        elif not re.search(ns.type,route_dict[(ns.dest_ip, ns.mask)]['next_hop'][ns.next_hop]['type'], re.I):
                            log.info('Ip destination {0}/{1} with nexthop {2} is type {3} - expected {4} on {4} route table'.\
                                       format(ns.dest_ip, ns.mask, ns.next_hop, route_dict[(ns.dest_ip, ns.mask)]['next_hop'][ns.next_hop]['type'],\
                                       ns.type, hdl.switchName))
                            loopuntil_result='fail'
                    else:
                        for nh in route_dict[(ns.dest_ip, ns.mask)]['next_hop'].keys():
                            if not re.search(ns.type, route_dict[(ns.dest_ip, ns.mask)]['next_hop'][nh]['type'], re.I):
                                log.info('Ip destination {0}/{1} with nexthop {2} is type {3} - expected {4} on {4} route table'.\
                                       format(ns.dest_ip, ns.mask, ns.next_hop, route_dict[(ns.dest_ip, ns.mask)]['next_hop'][nh]['type'],\
                                       ns.type, hdl.switchName))
                                loopuntil_result='fail'
                        
                                            
                if ns.interface:
                    int=utils.normalizeInterfaceName(log, ns.interface)
                    if ns.next_hop:
                        if ns.next_hop not in route_dict[(ns.dest_ip, ns.mask)]['next_hop'].keys():
                            loopuntil_result='fail'
                        
                        elif route_dict[(ns.dest_ip, ns.mask)]['next_hop'][ns.next_hop]['interface']!=int:
                            testResult('fail','Ip destination {0}/{1} with nexthop {2} is on interface {3} - expected {4} on {5} route table'.\
                                       format(ns.dest_ip, ns.mask, ns.next_hop, route_dict[(ns.dest_ip, ns.mask)]['next_hop'][ns.next_hop]['interface'],\
                                       int, hdl.switchName), log)
                            loopuntil_result='fail'
                    else:
                        nhresult='fail'
                        for nh in route_dict[(ns.dest_ip, ns.mask)]['next_hop'].keys():
                            if route_dict[(ns.dest_ip, ns.mask)]['next_hop'][nh]['interface']==int:
                                log.info('Ip destination {0}/{1} with nexthop {2} is on interface {3} on {4} route table'.\
                                       format(ns.dest_ip, ns.mask, nh, route_dict[(ns.dest_ip, ns.mask)]['next_hop'][nh]['interface'],\
                                       int, hdl.switchName))
                                nhresult='pass'
                        if nhresult=='fail':
                            loopuntil_result='fail'

            if loopuntil_result=='pass':
                break
            if loop==ns.iteration-1:
                self.result='fail'
            else:
                time.sleep(ns.interval)
         
        if self.result=='pass':
            testResult('pass','Ip route to destination {0}/{1} is on {2}'.format(ns.dest_ip, ns.mask, hdl.switchName), log)
        else:
            testResult('fail','Ip route to destination {0}/{1} is not on {2}'.format(ns.dest_ip, ns.mask, hdl.switchName), log) 


class verifyIpv6Route():
    '''  To verify given Ipv6 route is on the dut 
    Usage: 
    verifyIpv6Route(hdl1, log, '-dest 64:: -mask 64 -type ospf')
    verifyIpv6Route(hdl1, log, '-dest 128::128 -mask 128 -type direct -vrf test')
    
     '''
    def __init__(self,hdl,log,*args):
        self.result='pass'
        
        arggrammar={}
        arggrammar['dest']='-type str -required True'
        arggrammar['mask']='-type str -required True'
        arggrammar['next_hop']='-type str'
        arggrammar['interface']='-type str'
        arggrammar['type']='-type str'   
        arggrammar['vrf']='-type str'
        arggrammar['iteration']='-type int -default 1'
        arggrammar['interval']='-type int -default 30'
   
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        ns.dest=ipaddr.IPv6Address(ns.dest).exploded

        for loop in range(ns.iteration):
            if ns.vrf:
                route_dict=getIpv6RouteDict(hdl, log, '-vrf {0}'.format(ns.vrf))
            else:
                route_dict=getIpv6RouteDict(hdl, log)
            loopuntil_result='pass'
            if (ns.dest, ns.mask) not in route_dict.keys():
               log.info('Ipv6 destination {0}/{1} not in {2} route table'.format(ns.dest, ns.mask, hdl.switchName))
               loopuntil_result='fail'
            else:
                if ns.next_hop:
                    ns.next_hop=ipaddr.IPv6Address(ns.next_hop).exploded
                    if ns.next_hop not in route_dict[(ns.dest, ns.mask)]['next_hop'].keys():
                        log.info('Ipv6 destination {0}/{1} doesnt have nexthop {2} in {3} route table'.\
                                   format(ns.dest, ns.mask, ns.next_hop, hdl.switchName))
                        loopuntil_result='fail'
                        
                if ns.type:
                    if ns.next_hop:
                        if ns.next_hop not in route_dict[(ns.dest, ns.mask)]['next_hop'].keys():
                            loopuntil_result='fail'
                        
                        elif not re.search(ns.type,route_dict[(ns.dest, ns.mask)]['next_hop'][ns.next_hop]['type'], re.I):
                            log.info('Ipv6 destination {0}/{1} with nexthop {2} is type {3} - expected {4} on {4} route table'.\
                                       format(ns.dest, ns.mask, ns.next_hop, route_dict[(ns.dest, ns.mask)]['next_hop'][ns.next_hop]['type'],\
                                       ns.type, hdl.switchName))
                            loopuntil_result='fail'
                    else:
                        for nh in route_dict[(ns.dest, ns.mask)]['next_hop'].keys():
                            if not re.search(ns.type, route_dict[(ns.dest, ns.mask)]['next_hop'][nh]['type'], re.I):
                                log.info('Ipv6 destination {0}/{1} with nexthop {2} is type {3} - expected {4} on {4} route table'.\
                                       format(ns.dest, ns.mask, ns.next_hop, route_dict[(ns.dest, ns.mask)]['next_hop'][nh]['type'],\
                                       ns.type, hdl.switchName))
                                loopuntil_result='fail'
                        
                                            
                if ns.interface:
                    int=utils.normalizeInterfaceName(log, ns.interface)
                    if ns.next_hop:
                        if ns.next_hop not in route_dict[(ns.dest, ns.mask)]['next_hop'].keys():
                            loopuntil_result='fail'
                        
                        elif route_dict[(ns.dest, ns.mask)]['next_hop'][ns.next_hop]['interface']!=int:
                            testResult('fail','Ipv6 destination {0}/{1} with nexthop {2} is on interface {3} - expected {4} on {5} route table'.\
                                       format(ns.dest, ns.mask, ns.next_hop, route_dict[(ns.dest, ns.mask)]['next_hop'][ns.next_hop]['interface'],\
                                       int, hdl.switchName), log)
                            loopuntil_result='fail'
                    else:
                        nhresult='fail'
                        for nh in route_dict[(ns.dest, ns.mask)]['next_hop'].keys():
                            if route_dict[(ns.dest, ns.mask)]['next_hop'][nh]['interface']==int:
                                log.info('Ipv6 destination {0}/{1} with nexthop {2} is on interface {3} on {4} route table'.\
                                       format(ns.dest, ns.mask, nh, route_dict[(ns.dest, ns.mask)]['next_hop'][nh]['interface'],\
                                       int, hdl.switchName))
                                nhresult='pass'
                        if nhresult=='fail':
                            loopuntil_result='fail'

            if loopuntil_result=='pass':
                break
            if loop==ns.iteration-1:
                self.result='fail'
            else:
                time.sleep(ns.interval)
         
        if self.result=='pass':
            testResult('pass','Ipv6 route to destination {0}/{1} is on {2}'.format(ns.dest, ns.mask, hdl.switchName), log)
        else:
            testResult('fail','Ipv6 route to destination {0}/{1} is not on {2}'.format(ns.dest, ns.mask, hdl.switchName), log) 



class verifyMacAddressTableCount():
  "  To verify all or given set of MAC table counts are accurate\
  Usage: verifyMacAddressTableCount(hdl,log)\
  verifyMacAddressTableCount(hdl,log,'-dynamic 50')\
  verifyMacAddressTableCount(hdl,log,'-dynamic 50 -secure 20')\
verifyMacAddressTableCount(hdl,log,'-vlan 5 -dynamic 50 -secure 20')"
  def __init__(self,hdl,log,*args):
    self.result='pass'

    arggrammar={}
    arggrammar['vlan'] = '-type int'
    arggrammar['interface'] = ''
    arggrammar['dynamic']=''
    arggrammar['static']=''
    arggrammar['secure']=''
    arggrammar['overlay']=''
    arggrammar['total']=''
    arggrammar['oneMandatory']=[('vlan','interface','dynamic','static','secure','overlay','total')]
    flags=['dynamic','static','secure','overlay','total']
    failedflags=[]
    passedflags=[]

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    getoptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str",flags,"-")
    mactablecount=getMacAddressTableCountDict(hdl,log,getoptions)
    if ns.VALIDARGS:
        for flag in flags:
            if flag in ns.KEYS:
                if mactablecount[flag] != int(getattr(ns,flag)):
                    log.error("{0} expected:{1} actual:{2}".format(flag,getattr(ns,flag),mactablecount[flag]))    
                    failedflags.append(flag)
                else: 
                    passedflags.append(flag)
        if len(failedflags):
            testResult('fail',"{0} didn't match expected values".format(failedflags),log)
        elif len(passedflags):
            testResult('fail',"{0} matched expected values".format(passedflags),log)
    else:
         testResult('fail',"atleast one of the {0} need to be passed".format(flags),log)

class verifyFeatureState():
  "  verifyFeatureState - Method to verify feature state enabled/disabled \
         mandatory args: hdl, log, feature    \
        optional args: state, iterations, interval \
        Usage Example: verifyFeatureState(hdl, log, '-feature ospf') \
                verifyFeatureState(hdl, log, '-feature ospf,bfd -state disabled') \
                verifyFeatureState(hdl, log, '-feature ospf,bfd -state enabled -iterations 3 -interval 20')"
  
  def __init__(self, hdl, log, *args):
    self.result='pass'
   
    arggrammar={}
    arggrammar['feature'] = '-type str -required True'
    arggrammar['state'] = '-type str -default enabled'
    arggrammar['iterations'] = '-type int -default 1'
    arggrammar['interval']='-type int -default 30'
    arggrammar['listFlag']='-type bool -default True'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
 
    if ns.feature:
        if ns.listFlag:
            feature_list=strtolist(ns.feature)
        else:
            feature_list=[]
            #print('CHECK {0} of type {1}'.format(ns.feature, type(ns.feature)))
            tmp=ns.feature.split('\s')
            #print(tmp)
            for var in tmp:
                feature_list.append('_'.join(var.split()))
            #print(feature_list)
    else:
        testResult('fail','feature is required in arguments', log)
    
    for iteration in range(ns.iterations):
        feature_result=True
        #For each feature get state and compare with given/default value
        for feature in feature_list:
            log.info('the value of feature inside verifyFeatureState is %s' %feature)
            if feature == 'hsrp':
                 feature='hsrp_engine'
            if feature == 'nv overlay':
                 feature = 'nve'
            if feature == 'vn-segment-vlan-based':
                 feature = 'vnseg_vlan'
            if feature == 'tunnel-encryption':
                 feature = 'tun_enc_mgr'
#            if feature == 'vn-segment-vlan-based':
#                 feature ='vnseg_vlan'
            output=getFeatureState(hdl, log, '-feature {0}'.format(feature))
            log.info('the value of output is %s' %output)
            test=re.search(str(ns.state), output, flags=re.I)
            if not (re.search(str(ns.state), output, flags=re.I)):
                feature_result=False
                log.info('Iteration {0}-feature {1} is in state {2}, expected {3}'.format(iteration, feature, output, ns.state))
            else:
                log.info('Iteration {0}-feature {1} is in state {2}, expected {3}'.format(iteration, feature, output, ns.state))
        if feature_result or iteration == ns.iterations-1:
            break
        time.sleep(ns.interval)
    if not feature_result:
        testResult('fail','Failed to verify state -{0} for feature {1}'.format(ns.state, str(feature_list)),log)
    else:
        testResult('pass','State -{0} verified for features {1}'.format(ns.state, str(feature_list)),log)


class verifyClassMap():
  "  verifyClassMap - Method to verify match condition on class-map\
         mandatory args: hdl, log,match type. its value,    \
         type(qos/nqos/queuing/control-plane), name \
         Usage Example: \
         verifyClassMap(hdl,log,'-cname foo','-ctype qos','-mtype cos','-value 3') \
         verifyClassMap(hdl,log,'-match qos-group','-value 1','-type network-qos',\
         '-name pmap1') \
         verifyClassMap(hdl,log,'-match qos-group','-value 3', '-type queuing', '-name foo')"

  def __init__(self, hdl, log, *args):
    self.result='pass'

    arggrammar={}
    arggrammar['mtype'] = '-type str -required True'
    arggrammar['value'] = '-type str -required True'
    arggrammar['cname']='-type str -required True'
    arggrammar['ctype']='-type str -choices ["qos","network-qos","queuing","control-plane"]\
                         -required True'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if ns.cname == 'class-default':
        out_class_dict=getClassMapDict(hdl,log,'-type {0}'.format(ns.ctype))
    else:
        out_class_dict=getClassMapDict(hdl,log,'-type {0}'.format(ns.ctype),'-name {0}'.format(ns.cname))
    ctype=ns.ctype
    cname=ns.cname
    mtype=ns.mtype
    value=ns.value
        
    if (out_class_dict[(ctype,cname)][mtype]==value):
        log.info('Match {0} has value {1}'.format(ns.mtype, value))
        testResult('pass','Match {0} has value {1}'.format(ns.mtype, value),log)
    else:
        log.info('Match {0} does not have value {1}'.format(ns.mtype, value))
        testResult('fail','Match {0} does not have value {1}'.format(ns.mtype, value),log)

class verifyPolicyMap():
  "  verifyPolicyMap - Method to verify class-map condition on policy-map\
         mandatory args: hdl, log, match condition and its value    \
        optional args: type(qos/nqos/queuing/control-plane), name,iterations, interval \
        Usage Example: verifyPolicyMap(hdl, log, '-type qos -pname pmap1 -cname cmap1 \
                                       -action cos -value 3')"

  def __init__(self, hdl, log, *args):
    self.result='pass'

    arggrammar={}
    arggrammar['system']='-type bool -default False'
    arggrammar['interface']='-type str -format {0}|control-plane|all'.format(rex.INTERFACE_NAME)
    arggrammar['vlan'] = '-type str -format {0}'.format(rex.NUM)
    arggrammar['input'] = '-type bool -default False'
    arggrammar['output'] = '-type bool -default False'
    arggrammar['action'] = '-type str -required True'
    arggrammar['value'] = '-type str -required True'
    arggrammar['pname']='-type str -required True'
    arggrammar['cname']='-type str -required True'
    arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -required True'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if ns.interface:
        out_policy_dict=getPolicyMapDict(hdl,log,'-type {0}'.format(ns.type),'-interface {0}'.format(ns.interface))
    elif ns.system:
        out_policy_dict=getPolicyMapDict(hdl,log,'-type {0}'.format(ns.type),'-system {0}'.format(ns.system))
    elif ns.vlan:
        out_policy_dict=getPolicyMapDict(hdl,log,'-type {0}'.format(ns.type),'-vlan {0}'.format(ns.vlan))
    else:
        out_policy_dict=getPolicyMapDict(hdl,log,'-type {0}'.format(ns.type),'-name {0}'.format(ns.pname))
    type=ns.type
    pname=ns.pname
    cname=ns.cname
    action=ns.action
    value=ns.value
    print ('Policymap Dict is {0}'.format(out_policy_dict))
    print ('Checking Dict action is {0} and value is {1}'.format(out_policy_dict[(type,pname)][(type,cname)][action],value))
    if (out_policy_dict[(type,pname)][(type,cname)][action]==value):
        log.info('Policymap Action {0} has value {1} for class-map {2} under {3} on {4}'.format(action,value,cname,ns.interface,hdl.switchName))
        testResult('pass','Policymap Action {0} has value {1} for class-map {2} under {3} on {4}'.format(action,value,cname,ns.interface,hdl.switchName),log)
    else:
        log.info('Policymap Action {0} does not have value {1} for class-map {2} under {3} on {4}'.format(action,value,cname,ns.interface,hdl.switchName))
        testResult('fail','Policymap Action {0} does not have value {1} for class-map {2} under {3} on {4}'.format(action,value,cname,ns.interface,hdl.switchName),log) 

class verifyAppliedPolicy():
  "  verifyAppliedPolicy - Method to verify policy-map applied under system/Intf/vlan\
         mandatory args: hdl, log, policymap name and target    \
         Usage Example: verifyAppliedPolicy(hdl, log, '-type qos -pname pmap1 -target system')"

  def __init__(self, hdl, log, *args):
    self.result='pass'

    arggrammar={}
    arggrammar['target']='-type str -choices ["system","interface","vlan"] -required True'
    arggrammar['dir'] = '-type str -choices ["input","output"]'
    arggrammar['pname']='-type str -required True'
    arggrammar['cname']='-type str -default ""'
    arggrammar['module']='-type str -default ""'
    arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -required True'
    arggrammar['interface']='-type str -format {0}|control-plane|all'.format(rex.INTERFACE_NAME)
    arggrammar['vlan'] = '-type str'.format(rex.NUM)

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if ns.interface:
        out_policy_dict=getPolicyMapDict(hdl,log,'-type {0}'.format(ns.type),'-interface {0}'.format(ns.interface))
    elif ns.target=='system':
        out_policy_dict=getPolicyMapDict(hdl,log,'-type {0}'.format(ns.type),'-system True')
    elif ns.vlan:
        out_policy_dict=getPolicyMapDict(hdl,log,'-type {0}'.format(ns.type),'-vlan {0}'.format(ns.vlan))
    type=ns.type
    pname=ns.pname
    print ('Policymap Dict is {0}'.format(out_policy_dict))
    if (type,pname) not in out_policy_dict.keys():
        log.info('FAIL: Policymap name {0} of type {1} is not applied on switch {2}'.format(pname, type, hdl.switchName))
        testResult('fail','FAIL: Policymap name {0} of type {1} is not applied on switch {2}'.format(pname, type, hdl.switchName),log)
    elif (out_policy_dict[(type,pname)]) in out_policy_dict.keys():
        log.info('Policymap name {0} of type {1} is applied on switch {2}'.format(pname, type, hdl.switchName))
        testResult('pass','Policymap name {0} of type {1} is applied on switch {2}'.format(pname, type, hdl.switchName), log)
    if ns.type == 'control-plane':  # Check CoPP packets stats
        policy_cmap_dict = out_policy_dict.values()[0]
        cname = ns.cname
        if (type,cname) in policy_cmap_dict:  # Check if the class-map exists
          msg = 'class-map {0} of type {1} is applied'.format(cname,type)
          log.info(msg)
          testResult('pass', msg, log)
          cmap_dict = policy_cmap_dict[(type,cname)]
          if ns.module not in cmap_dict:  # Check if the module info exists
            msg = 'module {0} is not found under class-map {1} in copp policy-map'.format(ns.module, cname)
            log.info(msg)
            testResult('fail', msg, log)
          elif cmap_dict[ns.module]['transmitted packets'] == '0':  # Check number of transmit packets
            msg = 'transmitted packets is 0 in module {0} under class-map {1} in copp policy-map'.format(ns.module, cname)
            log.info(msg)
            testResult('fail', msg, log)
          elif cmap_dict[ns.module]['dropped packets'] != '0':  # Check number of dropped packets
            msg = 'dropped packets is not 0 in module {0} under class-map {1} in copp policy-map'.format(ns.module, cname)
            log.info(msg)
            testResult('fail', msg, log)
          else:
            msg = 'packets are transmitted in LC module {0} and not dropped under class-map {1} in copp policy-map'.format(ns.module, cname)
            log.info(msg)
            testResult('pass', msg, log)
            if hdl.device_type == 'sTOR':
              log.info('Skip FM check since device is sTOR')
            else:
              fm_transmit = False  # Check FM transmitted
              for k in cmap_dict:
                if k.isdigit() and int(k) in range(21,27):  # FM modules 21-26
                  if cmap_dict[k]['transmitted packets'] != '0':
                    fm_transmit = True
              if fm_transmit:
                msg = 'packets are transmitted in FM and under class-map {0} in copp policy-map'.format(cname)
                log.info(msg)
                testResult('pass', msg, log)
              else:
                msg = 'packets are not tramsitted in FM under class-map {0} in copp policy-map'.format(cname)
                log.info(msg)
                testResult('fail', msg, log)
        else:
          msg = 'class-map {0} of type {1} is not applied'.format(cname,type)
          log.info(msg)
          testResult('fail', msg, log)


class verifyTXQueueStats():
  """ Added by sandesub """
  def __init__(self,hdl,log, *args):
    self.result='pass'
    arggrammar={}
    arggrammar['intf']='-type str -required True' 
    arggrammar['qos_group']='-type str -required True' 
    arggrammar['tx_ucast_pkts']='-type str' 
    arggrammar['tx_oobfc_pkts']='-type str' 
    arggrammar['dropped_ucast_pkts']='-type str' 
    arggrammar['dropped_oobfc_pkts']='-type str' 
    arggrammar['interval']='-type int -default 10' 
    arggrammar['iterations']='-type int -default 1' 
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    input_qos_group=ns.qos_group
    intf=ns.intf
    stats_dict = getIntfQueuingQoSGroupStatsDict(hdl,log,'-intf {0}'.format(intf))
    for qos_group in stats_dict.keys():
      if input_qos_group == qos_group:
        for type in stats_dict[input_qos_group].keys():
          if type == 'Tx':
            if ns.tx_ucast_pkts:
              tx_ucast_pkts=ns.tx_ucast_pkts
              output_ucast_pkts = stats_dict[input_qos_group]['Tx']['Unicast']
              if tx_ucast_pkts == output_ucast_pkts:
                testResult('pass','TX stats for QOS GROUP {0} is MATCHING: Expected: {1} Actual: {2}'.format(input_qos_group,tx_ucast_pkts,output_ucast_pkts),log)
              else:
                testResult('FAIL','TX stats for QOS GROUP {0} is NOT MATCHING: Expected: {1} Actual: {2}'.format(input_qos_group,tx_ucast_pkts,output_ucast_pkts),log)
            if ns.tx_oobfc_pkts:
              tx_oobfc_pkts=ns.tx_oobfc_pkts
              output_oobfc_pkts = stats_dict[input_qos_group]['Tx']['OOBFC_Unicast']
              if tx_oobfc_pkts == output_oobfc_pkts:
                testResult('pass','TX stats for QOS GROUP {0} is MATCHING: Expected: {1} Actual: {2}'.format(input_qos_group,tx_oobfc_pkts,output_oobfc_pkts),log)
              else:
                testResult('FAIL','TX stats for QOS GROUP {0} is NOT MATCHING: Expected: {1} Actual: {2}'.format(input_qos_group,tx_oobfc_pkts,output_oobfc_pkts),log)
                self.result='fail'
          if type == 'Dropped':
            if ns.dropped_ucast_pkts:
              dropped_ucast_pkts=ns.dropped_ucast_pkts
              output_dropped_pkts = stats_dict[input_qos_group]['Dropped']['Unicast']
              if dropped_ucast_pkts == output_dropped_pkts:
                testResult('pass','Dropped stats for QOS GROUP {0} is MATCHING: Expected: {1} Actual: {2}'.format(input_qos_group,dropped_ucast_pkts,output_dropped_pkts),log)
              else:
                testResult('FAIL','Dropped stats for QOS GROUP {0} is NOT MATCHING: Expected: {1} Actual: {2}'.format(input_qos_group,dropped_ucast_pkts,output_dropped_pkts),log)
            if ns.dropped_oobfc_pkts:
              dropped_oobfc_pkts=ns.dropped_oobfc_pkts
              output_dropped_pkts = stats_dict[input_qos_group]['Dropped']['OOBFC_Unicast']
              if dropped_oobfc_pkts == output_dropped_pkts:
                testResult('pass','Dropped stats for QOS GROUP {0} is MATCHING: Expected: {1} Actual: {2}'.format(input_qos_group,dropped_oobfc_pkts,output_dropped_pkts),log)
              else:
                testResult('FAIL','Dropped stats for QOS GROUP {0} is NOT MATCHING: Expected: {1} Actual: {2}'.format(input_qos_group,dropped_oobfc_pkts,output_dropped_pkts),log)
                self.result='fail'
              
           
            

### QoS verifications end ###

class verifySpanningTreeBridgePriority():
  "  Added by sandesub\
  Description: checks the bridge-priority configured on the switch\
  Sample Usage:\
  verifySpanningTreeBridgePriority(hdl,log, **stp_bp_dict) - verification across all vlans\
  verifySpanningTreeBridgePriority(hdl,log, '-vlan <vlan-id>', **stp_bp_dict)  - verification for specific vlans\
  verifySpanningTreeBridgePriority(hdl,log, '-msti <msti-id>', **stp_bp_dict)  - verification for specific MSTIs"
  def __init__(self,hdl,log, *args, **stp_bp_dict):
    self.result='pass'
    self.proc_name='verifySpanningTreeBridgePriority'
    arggrammar={}
    arggrammar['vlan']='-type str'
    arggrammar['msti']='-type str'
    arggrammar['mutualExclusive'] =[('vlan','msti')]
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.vlan:
        output_stp_bp_dict = getSpanningTreeBridgePriorityDict(hdl,log,'-vlan ' + str(parse_output.vlan))
    elif parse_output.msti:
        output_stp_bp_dict = getSpanningTreeBridgePriorityDict(hdl,log,'-msti ' + str(parse_output.msti))
    else:
        output_stp_bp_dict = getSpanningTreeBridgePriorityDict(hdl,log)
    if stp_bp_dict:
        if (compareVars(stp_bp_dict,output_stp_bp_dict,log) == 'pass'):
                #testResult('pass','All STP bridge-priorites are correct. Expected dict: {0} Actual dict: {1}'.format(stp_bp_dict,output_stp_bp_dict),log)
                pass
        else:
                testResult('fail','STP bridge-priorities are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(stp_bp_dict,output_stp_bp_dict),log)
                self.result='fail'
    else:
        testResult('fail','{0}:MANDATORY DICT argument NOT passed'.format(self.proc_name),log)
        self.result='fail'


class verifySpanningTreePortCost():
  "  Added by sandesub\
  Description: checks the STP cost configured on the interface\
  Sample Usage:\
  verifySpanningTreePortCost(hdl,log, '-intf <>', **stp_cost_dict) - verification across all vlans\
  verifySpanningTreePortCost(hdl,log, '-intf <>', '-vlan <vlan-id>', **stp_cost_dict)  - verification for specific vlans\
  verifySpanningTreePortCost(hdl,log, '-intf <>', '-msti <msti-id>', **stp_cost_dict)  - verification for specific MSTIs"
  def __init__(self,hdl,log, *args, **stp_cost_dict):
    self.result='pass'
    self.proc_name='verifySpanningTreePortCost'
    arggrammar={}
    arggrammar['vlan']='-type str'
    arggrammar['msti']='-type str'
    arggrammar['intf']='-type str'
    arggrammar['mutualExclusive'] =[('vlan','msti')]
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    output_stp_cost_dict = getSpanningTreePortCostDict(hdl,log,'-intf ' + str(parse_output.intf))
    if stp_cost_dict:
        if (compareVars(stp_cost_dict,output_stp_cost_dict,log) == 'pass'):
                testResult('pass','All STP costs are correct. Expected dict: {0} Actual dict: {1}'.format(stp_cost_dict,output_stp_cost_dict),log)
        else:
                testResult('fail','STP costs are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(stp_cost_dict,output_stp_cost_dict),log)
                self.result='fail'
    else:
        testResult('fail','{0}:MANDATORY DICT argument NOT passed'.format(self.proc_name),log)
        self.result='fail'

class verifySpanningTreePortPriority():
  "  Added by sandesub\
  Description: checks the STP port-priority configured on the interface\
  Sample Usage:\
  verifySpanningTreePortPriority(hdl,log, '-intf <>', **stp_port_priority_dict) - verification across all vlans\
  verifySpanningTreePortPriority(hdl,log, '-intf <>', '-vlan <vlan-id>', **stp_port_priority_dict)  - verification for specific vlans\
  verifySpanningTreePortPriority(hdl,log, '-intf <>', '-msti <msti-id>', **stp_port_priority_dict)  - verification for specific MSTIs"
  def __init__(self,hdl,log, *args, **stp_port_priority_dict):
    self.result='pass'
    self.proc_name='verifySpanningTreePortPriority'
    arggrammar={}
    arggrammar['vlan']='-type str'
    arggrammar['msti']='-type str'
    arggrammar['intf']='-type str'
    arggrammar['interval']='-type int -default 10'
    arggrammar['iterations']='-type int -default 1'
    arggrammar['mutualExclusive'] =[('vlan','msti')]
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    iterations=parse_output.iterations
    interval=parse_output.interval

    if stp_port_priority_dict:
        loop=0
        while loop<iterations:
            output_stp_port_priority_dict = getSpanningTreePortPriorityDict(hdl,log,'-intf ' + str(parse_output.intf))
            if (compareVars(stp_port_priority_dict,output_stp_port_priority_dict,log) == 'fail'):
                loop+=1
                if loop == iterations:
                    self.result='fail'
                    testResult('fail','STP port-priorities are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(stp_port_priority_dict,output_stp_port_priority_dict),log)
                else:
                    time.sleep(interval)
            else:
                break
    else:
        testResult('fail','{0}:MANDATORY DICT argument NOT passed'.format(self.proc_name),log)
        self.result='fail'


class verifyTcamRegionSize():
  """  Added by sandesub\
  Description: Verifies the size of a given region in ACL TCAM\
  Sample Usage:\
  verifyTcamRegionSize(hdl,log, **tcam_region_dict) - verification across all regions\
  verifyTcamRegionSize(hdl,log, '-region <>', '-size <>')  - verification for specific regions\
  """
  def __init__(self,hdl,log, *args, **tcam_region_dict):
    self.result='pass'
    self.proc_name='verifyTcamRegionSize'
    arggrammar={}
    arggrammar['region']='-type str'
    arggrammar['size']='-type str'
    arggrammar['interval']='-type int -default 10'
    arggrammar['iterations']='-type int -default 1'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    iterations=ns.iterations
    interval=ns.interval

    if tcam_region_dict:
        loop=0
        while loop<iterations:
            output_tcam_region_dict = getTcamRegionDict(hdl,log)
            if (compareVars(tcam_region_dict,output_tcam_region_dict,log) == 'fail'):
                loop+=1
                if loop == iterations:
                    self.result='fail'
                    testResult('fail','TCAM region sizes are INCORRECT. Expected dict: {0} Actual dict: {1}'.format(tcam_region_dict,output_tcam_region_dict),log)
                else:
                    time.sleep(interval)
            else:
                break
    else:
        output_size = getTcamRegionSize(hdl,log,'-region {0}'.format(ns.region))
        if ns.size == output_size:
            testResult('pass','Region {0} size: Expected Size: {1}, Actual Size {2}'.format(ns.region,ns.size,output_size), log)
        else:
            testResult('fail','Region {0} size: Expected Size: {1}, Actual Size {2}'.format(ns.region,ns.size,output_size), log)
            
            


class verifyRaclCC():
  """  Added by sandesub\
  Description: Verifies if RACL CC passes/fails\
  Sample Usage:\
  verifyRaclCC(hdl,log, '-result PASSED -module 7') - verify if RACL CC passes on module 7\
  """
  def __init__(self,hdl,log, *args):
    self.result='pass'
    self.proc_name='verifyRaclCC'
    arggrammar={}
    arggrammar['result']='-type str'
    arggrammar['module']='-type str'
    arggrammar['interface']='-type str'
    arggrammar['direction']='-type str -choices ["in","out"]'
    arggrammar['interval']='-type int -default 10'
    arggrammar['iterations']='-type int -default 1'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    output_result = getResultRaclCC(hdl,log,'-module {0}'.format(ns.module)) 
    if ns.result == output_result[0]:
        testResult('pass','Expected Result for module {0}: {1}, Actual Result {2}'.format(ns.module,ns.result,output_result[0]), log)
        del output_result[0]
        out_dict=convertListToDict(output_result,['port','direction'],['port'])
        print (out_dict)
        
    else:
        testResult('fail','Expected Result for module {0}: {1}, Actual Result {2}'.format(ns.module,ns.result,output_result[0]), log)



class verifyVpcDomain():
    '''
    "  verifyVpcDomain - Method to verify following
      1. Vpc domain configured
      2. Vpc peer keep-alive status
      3. Vpc peer-link status
      4. Vpc global consistency 
      5. Vpc vlans consistency
      6. Vpc status and Po status 
      7. Status of all members of Vpc port-channels
    
     mandatory args: hdl, log
     optional args: vpc_list, state, vpc_dict
     Usage Example: 
         verifyVpcDomain(hdl, log)
         verifyVpcDomain(hdl, log, '-vpc_list 1,2,3')
         verifyVpcDomain(hdl, log, '-vpc_list 1,2,3 -status down')

        in_dict={}
        in_dict['1']={}
        in_dict['2']={}
        in_dict['1']['Status']='up'
        in_dict['2']['Status']='down'         
   
        verifyVpcDomain(hdl, log, **in_dict)

        '''
    
    def __init__(self, hdl, log, *args, **vpc_dict):
        
        self.result='pass'
       
        arggrammar={}
        arggrammar['vpc_list'] = ''
        arggrammar['status'] = '-type str -default up'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        
        print ('ns is {0}'.format(ns))
    
        if vpc_dict:
            print (vpc_dict)
            vpc_up_list=[]
            vpc_down_list=[]
            print ('keys is {0}'.format(vpc_dict.keys()))
            for vpc in vpc_dict.keys():
                print ('vpc is {0}'.format(vpc))
                if vpc_dict[vpc]['Status']=='up':
                    vpc_up_list.append(vpc)
                elif vpc_dict[vpc]['Status']=='down':
                    vpc_down_list.append(vpc)
                else:
                    self.log.info('Invalid status {0} for vpc {1}'.format(vpc_dict[vpc]['Status'], vpc))
            vpc_up_list_str=listtostr(vpc_up_list)
            vpc_down_list_str=listtostr(vpc_down_list)
                        
        if ns.vpc_list:
            vpc_list=ns.vpc_list
            print ('vpc_list is {0}'.format(vpc_list))
            vpc_str=ns.vpc_list
        else:
            vpc_list=getVpcList(hdl,log)
            vpc_str=listtostr(vpc_list)
    
        vpc_status=ns.status
     
    
        if ns.vpc_list and vpc_dict:
            log.info('Invalid arguments, please use either vpc_list or vpc_dict as arguments')
        
        ### Verify Vpc global status/parameters
        vpc_domain_id=getVpcDomainId(hdl, log)
        if not vpc_domain_id:
            testResult('fail', 'Vpc domain id is not configured', log)
            return
        else:
            verifykeepalive=verifyVpcPeerKeepAlive(hdl, log)
            if verifykeepalive.result=='fail':
                testResult('fail', 'Vpc keep-alive status not up', log)
            else:
                verifypeerlink=verifyVpcPeerLinkStatus(hdl, log)
                if verifypeerlink.result=='fail':
                    testResult('fail', 'Vpc peer link status not up', log)
                    return
                else:
                    vpcglobalconsistency=verifyVpcConsistencyParameters(hdl, log)
                    if vpcglobalconsistency.result=='fail':
                        testResult('fail', 'Vpc global consistency is not success', log)
                    else:
                        vpcvlanconsistency=verifyVpcConsistencyParameters(hdl, log, '-flag vlans')
                        if vpcvlanconsistency.result=='fail':
                            testResult('fail', 'Vpc vlan consistency is not success', log)
                        else:
                            testResult('pass','Vpc domain is up', log)
            if vpc_dict:
                verifyvpc=verifyVpcs(hdl, log, **vpc_dict)
                if verifyvpc.result=='fail':
                    testResult('fail','vpc verification failed', log)
                    
                if vpc_up_list:
                    verifyvpcmembersup=verifyVpcMembers(hdl, log, '-vpc_list {0} -status up'.format(vpc_up_list_str))
                    if verifyvpcmembersup.result=='fail':
                        testResult('fail','vpc verification failed', log)
                    
                if vpc_down_list:
                    verifyvpcmembersdown=verifyVpcMembers(hdl, log, '-vpc_list {0} -status down'.format(vpc_down_list_str))
                    if verifyvpcmembersdown.result=='fail':
                        testResult('fail','vpc verification failed', log)
                    else:
                        testResult('pass','vpc verification passed for dict {0}'.format(vpc_dict), log)
    
            else:
                verifyvpc=verifyVpcs(hdl, log, '-vpc_list {0} -status {1}'.format(vpc_str, vpc_status))
                verifyvpcmembers=verifyVpcMembers(hdl, log, '-vpc_list {0} -status {1}'.format(vpc_str, vpc_status))
                if verifyvpc.result=='fail' or verifyvpcmembers.result=='fail':
                    testResult('fail','vpc verification failed', log)
                else:
                    testResult('pass','Vpc verifications pass for vpc list {0}'.format(vpc_list), log)

class verifySyslogs():

  '''
    "  verifySyslogs - Method to verify following
      1. None of the errors as specified by syslogcheckdict is seen during stimuli/trigger execution
      2. None of the logs of specified levels seen [Have option to ignore known log messages reported with higher levels)
    
     mandatory args: self, hdl, log, startlog (Snapshot taken in precheck)
     optional args: -ignore_list to ignore any specific error messages
     Usage Example: 
         verifySyslogs(hdl, log, lastlog)
         verifySyslogs(hdl, log, lastlog, '-ignore_ist PLATFORM-2-MOD_PWRUP

        '''

  def __init__(self,hdl,log,syslogcheckdict,startlog, *args):

    self.result='pass'
    arggrammar={}
    arggrammar["ignore_list"]='-type list'
    arggrammar["mandatory_list"]='-type list'
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    mandatory_list={}
    if startlog:
        logoutput=hdl.iexec("show logging last 9999 | begin \"{0}\"".format(startlog))
    else:
        logoutput=hdl.iexec("show logging last 9999")
    syslogcheckpassed=True
    for alarm in syslogcheckdict['errors'].keys():
        if parseoutput.ignore_list and alarm in parseoutput.ignore_list:
            continue
        searchlist=re.findall(alarm,logoutput)
        if len(searchlist):
            if parseoutput.mandatory_list and alarm in parseoutput.mandatory_list:
                mandatory_list[alarm]=True
            else:
                log.error("{0} {1}".format(alarm,syslogcheckdict['errors'][alarm]))
                syslogcheckpassed=False

    if not syslogcheckpassed:
          testResult('fail','syslog check failed, details above',log)

    if not 'warnings' in syslogcheckdict.keys():
        return 

    syslogcheckpassed=True
    log.info("The syslogs are: {0}".format(logoutput))
    error_list = []
    for level in strtoexpandedlist(syslogcheckdict['warnings']['levels']):
        msgs=list(re.findall("\%([A-Z_].+\-{0}\-+[^:]+)".format(level),logoutput))
        log.info("the level {0}  msg : {1}".format(level,msgs))
        if 'ignore_list' in syslogcheckdict['warnings'].keys():
            ignore_list=syslogcheckdict['warnings']['ignore_list'].keys()
            if parseoutput.ignore_list:
                for element in parseoutput.ignore_list:
                    ignore_list.append(element)
            for ignore_element in ignore_list:
                while ignore_element in msgs:
                       msgs.pop(msgs.index(ignore_element))

            if parseoutput.mandatory_list:
                for mandatory_element in parseoutput.mandatory_list:
                    while mandatory_element in msgs:
                         mandatory_list[mandatory_element]=True
                         msgs.pop(msgs.index(mandatory_element))
        if not len(msgs):
          log.info("Inside checking length") 
          continue
        log.error("severity level {0} messages found".format(level))
        log.error("Messages are {0}".format(msgs))
        msgs = list(set(msgs))
        error_list.append(msgs)
        syslogcheckpassed=False
  
    if parseoutput.mandatory_list:
        for alarm in parseoutput.mandatory_list:
            if alarm not in mandatory_list.keys():
                log.error("syslog {0} is expected to be seen in output but not seen".format(alarm))
                syslogcheckpassed=False

    if not syslogcheckpassed:
          testResult('fail','syslog check failed, details in the logfile prior to this message',log)
          testResult('fail','syslog check failed error logs: {0}'.format(error_list),log)

class verifyStatsForACLEntry():
    """ Added by sandesub
    This method verifies the ACL stats for a given ACL and entry
    """
    def __init__(self,hdl, log, *args):
        self.result='pass'
        arggrammar={}
        arggrammar['type']='-type str -required True -choices ["ip","ipv6","mac","vlan"]'
        arggrammar['acl_name']='-type str'
        arggrammar['seq_no']='-type str'
        arggrammar['count']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
        output_count = getStatsForACLEntry(hdl,log,'-type {2} -acl_name {0} -seq_no {1}'.format(ns.acl_name,ns.seq_no,ns.type))
        if output_count == -1:
            testResult('fail','ACL stats is being checked without being enabled',log)
            self.result='fail'
        else:    
            if (ns.count == output_count):     
                testResult('pass','expected count {0} matches with actual count {1} for ACL {2} seq-no {3}'.format(ns.count,output_count,ns.acl_name,ns.seq_no),log)
            else:
                testResult('fail','expected count {0} DOES NOT match with actual count {1} for ACL {2} seq-no {3}'.format(ns.count,output_count,ns.acl_name,ns.seq_no),log)
                self.result='fail'
        

class verifyMacTable():

  def __init__(self,hdl,log,expecteddict,*args):
    self.result = 'pass'
    arggrammar={}
    arggrammar['dynamic']=''
    arggrammar['module']=''
    arggrammar['negative']='-type bool -default False'
    arggrammar['no_other_entries']='-type bool -default False'
    arggrammar['address']= ''
    arggrammar['interface']= ''
    arggrammar['secure']= '-type bool'
    arggrammar['static']= '-type bool'
    arggrammar['vlan']= '-type int'


    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    optionstr=parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str",['negative','no_other_entries'],"-")

    actualdict=utils.getMacAddressTableDict(hdl,log,optionstr)

    compareresult=compareVars(expecteddict,actualdict,log,'-allfailures')
    if ns.negative:
        if compareresult == 'pass':

            #testResult('fail','MAC Table Verification: Unexpected entries {0} exist in mac address table output {1}'.format(expecteddict,actualdict),log)
            log.info('MAC Table Verification failed: Unexpected entries {0} exist in mac address table output {1}'.format(expecteddict,actualdict))
            testResult('fail','MAC Table Verification: Unexpected entries exist in mac address table output ',log)
        else:
            #testResult('pass','MAC Table Verificaiton: Unexpected entries dont {0} exist in mac address table output {1}'.format(expecteddict,actualdict),log)
            testResult('pass','MAC Table Verificaiton: Unexpected entries dont exist in mac address table output ',log)
    else:
        if compareresult == 'fail':
            #testResult('fail','MAC Table Verification failed: expected entries {0} dont exist in mac address table output {1}'.format(expecteddict,actualdict),log)
            log.info('MAC Table Verification failed: expected entries {0} dont exist in mac address table output {1}'.format(expecteddict,actualdict))
            testResult('fail','MAC Table Verification failed: expected entries dont exist in mac address table output '.format(expecteddict,actualdict),log)
        else:
            #testResult('pass','MAC Table Verification: expected entries {0} exist in mac address table output {1}'.format(expecteddict,actualdict),log)
            testResult('pass','MAC Table Verification passed ',log)

    if ns.no_other_entries:
        if len(actualdict.keys()) != len(expecteddict.keys()):
            testResult('fail','MAC Address table Expected only these entries: {0} but found: {1}'.format(expecteddict,actualdict),log)
        else:
            testResult('fail','No additional entires found in the mac address table as expected'.format(expecteddict,actualdict),log)
            


class verifyCdpNeighbor():
    
    ''' Verifies cdp neighbor on a given interface
     Mandatory Args: hdl, log, neighbor, interface
     Optional Args: neighbor_interface, verify_iterations, verify_interval
     Sample Usage:
     verifyCdpNeighbor(hdl, log, '-neighbor N7K4-vdc2 -interface eth3/1')
     verifyCdpNeighbor(hdl, log, '-neighbor N7K4-vdc2 -interface eth3/1 -neighbor_interface eth3/13')
     '''
     

    def __init__(self,hdl,log,*args):
        self.result = 'pass'
        arggrammar={}
        arggrammar['interface']='-type str -required True'
        arggrammar['neighbor']='-type str -required True'
        arggrammar['neighbor_interface']='-type str'
        arggrammar['verify_iterations']='-type int -default 1' 
        arggrammar['verify_interval']='-type int -default 5'         
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface=utils.normalizeInterfaceName(log, ns.interface)
        
        for iteration in range(ns.verify_iterations):
            log.info('Begin iteration number {0} to check cdp neighbor for interface {1}'.format(iteration,interface))

            cdp_output=utils.getCdpNeighborDict(hdl, log,'-interface {0}'.format(interface))
            if not cdp_output:
                fail_msg='Fail:No CDP neighbor found for interface {0}'.format(interface)
            else:
                if not re.search('^{0}\([a-zA-Z-0-9]+\)$'.format(ns.neighbor),cdp_output[interface]['peerdevice'].strip()):
                    fail_msg='Fail:CDP neighbor was not correct on interface {0} in CDP neighbor, expected: {1}, actual: {2}'\
                       .format(interface,ns.neighbor,cdp_output[interface]['peerdevice'])
                else:
                    if ns.neighbor_interface:
                        peer_int=utils.normalizeInterfaceName(log,ns.neighbor_interface)
                        if 'peerport' in cdp_output[interface].keys():
                            if cdp_output[interface]['peerport']!=peer_int:
                                fail_msg='Fail:CDP neighbor interface was not correct on interface {0} in CDP neighbor, expected: {1}, actual: {2}'\
                                    .format(interface,peer_int,cdp_output[interface]['peerport'])
                            else:
                                log.info('CDP neighbor verified on interface {0} on {1}'.format(ns.interface, hdl.switchName))
                                return
                        else:
                            fail_msg='Fail:CDP neighbor interface {0} on {1} not in cdp neighbor for {2} on {3}'\
                                .format(peer_int, ns.neighbor, interface, hdl.switchName)
                    else:
                        log.info('CDP neighbor verified on interface {0} on {1}'.format(ns.interface, hdl.switchName))
                        return

            if iteration < ns.verify_iterations-1:
                log.info('Iteration {0}: {1}'.format(iteration,fail_msg))
                time.sleep(ns.verify_interval)
            else:
                utils.testResult('fail',fail_msg,log)


class verifyLldpNeighbor():
    
    ''' Verifies lldp neighbor on a given interface
     Mandatory Args: hdl, log, neighbor, interface
     Optional Args: neighbor_interface, verify_iterations, verify_interval
     Sample Usage:
     verifyLldpNeighbor(hdl, log, '-neighbor N7K4-vdc2 -interface eth3/1')
     verifyLldpNeighbor(hdl, log, '-neighbor N7K4-vdc2 -interface eth3/1 -neighbor_interface eth3/13')
     '''
     

    def __init__(self,hdl,log,*args):
        self.result = 'pass'
        arggrammar={}
        arggrammar['neighbor']='-type str -required True'
        arggrammar['interface']='-type str -required True'
        arggrammar['neighbor_interface']='-type str'     
        arggrammar['verify_iterations']='-type str -default 2' 
        arggrammar['verify_interval']='-type str -default 10'         
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface=utils.normalizeInterfaceName(log, ns.interface)
        
        if not utils.loop_until("utils.getLldpNeighborCount",(hdl, log,'-intf {0}'.format(interface)),1,'-iteration {0} -interval {1}'.format(ns.verify_iterations,ns.verify_interval)):
            utils.testResult('fail','Fail:LLDP neighbors was not found on interface {0} of {1}'.format(interface,hdl.switchName), log)
            self.result='fail'
            return
        
        lldp_output=utils.getLldpNeighborDict(hdl, log,'-intf {0}'.format(interface))
        log.info(lldp_output)
#        if lldp_output[interface]['peer']!= ns.neighbor:
# Added search for neighbor with DNS name 
        if not re.search(ns.neighbor,lldp_output[interface]['peer']):

            utils.testResult('fail','Fail:LLDP neighbor on {3} was not correct on interface {0}, expected: {1}, actual: {2}'\
             .format(interface,ns.neighbor,lldp_output[interface]['peer'],hdl.switchName),log)         
            self.result='fail'
            return
        else:
            if ns.neighbor_interface:
                 peer_int=utils.normalizeInterfaceName(log,ns.neighbor_interface)
                 if 'peer_intf' in lldp_output[interface].keys():
                     if lldp_output[interface]['peer_intf']!=peer_int:
                         utils.testResult('fail','Fail:LLDP neighbor interface on {3} was not correct on interface {0}, expected: {1}, actual: {2}'\
                         .format(interface,peer_int,lldp_output[ns.interface]['peer_intf'],hdl.switchName), log)
                         self.result='fail'
                     else:
                        log.info('LLDP neighbor verified on interface {0} on {1}'.format(ns.interface, hdl.switchName))
                        #utils.testResult('pass','LLDP neighbor verified on interface {0} on {1}'\
                        # .format(ns.interface, hdl.switchName), log)
                 else:
                     utils.testResult('fail','Fail:LLDP neighbor interface {0} on {1} not in lldp neighbor for {2} on {3}'\
                     .format(peer_int, ns.neighbor, interface, hdl.switchName), log)                      
            else:
                log.info('LLDP neighbor verified on interface {0} on {1}'.format(ns.interface, hdl.switchName))
                #utils.testResult('pass','LLDP neighbor verified on interface {0} on {1}'\
                #    .format(ns.interface, hdl.switchName), log)



def parseFwdDictUnicastL2( log, args):

    arggrammar={}
    arggrammar['mac_count']='-type int'
    arggrammar['static_mac_count']='-type int'
    arggrammar['dynamic_mac_count']='-type int'
    arggrammar['threshold']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns


def parseFwdDictUnicastL3( log, args):

    arggrammar={}
    arggrammar['route_count']='-type int'
    arggrammar['path_count']='-type int'
    arggrammar['ospf_count']='-type int'
    arggrammar['ospfv3_count']='-type int'
    arggrammar['bgp_count']='-type int'
    arggrammar['eigrp_count']='-type int'
    arggrammar['hsrp_count']='-type int'
    arggrammar['vrrp_count']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns



def parseFwdDictMulticastL2( log, args):
    arggrammar={}
    arggrammar['igmp_snooping_group_count']='-type int'
    arggrammar['l2_mroute_count']='-type int'
    arggrammar['mroute_count']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns


def parseFwdDictMulticastL3( log, args):
    arggrammar={}
    arggrammar['mroute_count']='-type int'
    arggrammar['star_g_count']='-type int'
    arggrammar['s_g_count']='-type int'
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )
    return ns



class verifyForwardingCount():

    """ 
    VerifyForwardingCount - To be used in SIT Automation, verifies the number of forwarding entries
    for L2/L3 in RIB/MAC and FIB for unicast and multicast based on what is provided in a dict. 
    We should call this after every SIT stimuli
    """

    def __init__(self, sw_hdl_dict, log, fwd_dict, *args):


        self.result='pass'

        arggrammar={}
        arggrammar['l2_unicast'] = '-type bool -default True'
        arggrammar['l2_ipv4_multicast'] = '-type bool -default True'
        arggrammar['l3_ipv4_multicast'] = '-type bool -default True'
        arggrammar['l3_ipv4_unicast'] = '-type bool -default True'
        arggrammar['l3_ipv6_unicast'] = '-type bool -default True'
        arggrammar['l3_ipv6_multicast'] = '-type bool -default False'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

        for node in fwd_dict.keys():

            hdl = sw_hdl_dict[node]
            
            if ns.l2_unicast:

                pi_ns=parseFwdDictUnicastL2( log, fwd_dict[node]['unicast']['l2']['pi'] )
                pd_ns=parseFwdDictUnicastL2( log, fwd_dict[node]['unicast']['l2']['pd'] )

                mac_dict=utils.getMacAddressTableCountDict( hdl, log )

                pd_mac_dict_lc={}

                for lc_no in utils.getLineCardList( hdl, log ):
                   pd_mac_dict_lc[lc_no]={}
                   pd_mac_dict_lc[lc_no]=utils.getHardwareMacTableCount( hdl, log, '-module {0}'.format(lc_no))
                   pd_mac_dict=pd_mac_dict_lc[lc_no]
               
                lc_list=utils.getLineCardList( hdl, log )
                lc_no=lc_list[0]


                # Build the Hardware static and dynamic count
                pd_static_mac_dict_lc={}
                pd_dynamic_mac_dict_lc={}

                pd_static_mac_dict_lc=utils.getHardwareMacTableCount( hdl, log, '-module {0}     \
                      -flag static'.format(lc_no))
                pd_dynamic_mac_dict_lc=utils.getHardwareMacTableCount( hdl, log, '-module {0}     \
                      -flag dynamic'.format(lc_no))
                


                # Verify the HW MAC entries are consistenct across all LCs                
                for lc_no in utils.getLineCardList( hdl, log ):

                    pd_mac_count_lc=len(pd_mac_dict_lc[lc_no])

                    if int( pd_mac_count_lc ) != int( pd_mac_dict ):

                        msg='''ERROR !! PD MAC count of all line cards not matching LCs = {0} {1}'''.format( \
                             lc_no, len(pd_mac_dict_lc) )
                        testResult( 'fail', msg, log )


                if pi_ns.mac_count is not None:
                    if int( mac_dict['total'] ) != int( pi_ns.mac_count ):
                        if pi_ns.threshold is not None:
                            msg='ERROR !! Expected Total PI MAC count = {0}, actual Total PI MAC count = {1},   \
                               Count not MATCHING !!'.format( pi_ns.mac_count, mac_dict['total'] )
                            testResult( 'fail', msg, log )
                        else: 
                            diff = distance( int ( mac_dict['total'] ), int( pi_ns.mac_count ) )
                            if int( diff ) > int( pi_ns.threshold ):
                                msg='ERROR !! Expected Total PI MAC count = {0}, actual Total PI MAC count      \
                                 = {1}, Threshold = {2} !!'. format( pi_ns.mac_count, mac_dict['total'],        \
                                 pi_ns.threshold )
                                testResult( 'fail', msg, log )


                if pi_ns.static_mac_count is not None:
                    if int( mac_dict['static_user_defined'] ) != int( pi_ns.static_mac_count ):
                        msg='ERROR !! Expected PI User defined static MAC count = {0},                         \
                           actual PI User defined STATIC MAC count = {1}, count not matching                   \
                           '.format( pi_ns.mac_count, mac_dict['total'] )
                        testResult( 'fail', msg, log )


                if pi_ns.dynamic_mac_count is not None:
                    if int( mac_dict['dynamic'] ) != int( pi_ns.dynamic_mac_count ):
                        if pi_ns.threshold is not None:
                            msg='ERROR !! Expected dynamic PI MAC count = {0}, actual dynamic PI MAC count     \
                                = {1}, Count not MATCHING !!'.format( pi_ns.dynamic_mac_count,                 \
                                mac_dict['dynamic'] )
                            testResult( 'fail', msg, log )
                        else: 
                            diff = distance( int ( mac_dict['dynamic'] ), int( pi_ns.dynamic_mac_count ) )
                            if int( diff ) > int( pi_ns.threshold ):
                                msg='ERROR !! Expected dynamic PI MAC count = {0}, actual dynamic PI MAC count  \
                                 = {1}, Threshold = {2} !!'. format( pi_ns.dynamic_mac_count,                   \
                                 mac_dict['dynamic'], pi_ns.threshold )
                                testResult( 'fail', msg, log )

                print('%%%%% pd_mac_dict_lc %%%%', pd_mac_dict_lc )

                if pd_ns.mac_count is not None:

                  for lc_no in utils.getLineCardList( hdl, log ):

                    if int( pd_mac_dict_lc[lc_no] ) != int( pd_ns.mac_count ):

                        if pd_ns.threshold is not None:

                            msg='ERROR !! Expected Total PD MAC count = {0}, actual Total PD MAC count = {1},   \
                               Count not MATCHING !!'.format( pd_ns.mac_count, pd_mac_dict_lc[lc_no] )
                            testResult( 'fail', msg, log )

                        else:

                            diff = distance( int ( pd_mac_dict_lc[lc_no] ), int( pd_ns.mac_count ) )

                            if int( diff ) > int( pd_ns.threshold ):
                                msg='ERROR !! Expected Total PD MAC count = {0}, actual Total PD MAC count      \
                                 = {1}, Threshold = {2} !!'. format( pd_ns.mac_count,                           \
                                 pd_mac_dict_lc[lc_no], pd_ns.threshold )
                                testResult( 'fail', msg, log )


                if pd_ns.static_mac_count is not None:
                    if int( pd_static_mac_dict_lc ) != int( pd_ns.static_mac_count ):
                        msg='ERROR !! Expected PD User defined static MAC count = {0},                         \
                           actual PD User defined STATIC MAC count = {1}, count not matching                   \
                           '.format( pd_ns.mac_count, pd_static_mac_dict_lc )
                        testResult( 'fail', msg, log )


                if pd_ns.dynamic_mac_count is not None:
                    if int( pd_dynamic_mac_dict_lc ) != int( pd_ns.dynamic_mac_count ):
                        if pd_ns.threshold is not None:
                            msg='ERROR !! Expected dynamic PD MAC count = {0}, actual dynamic PD MAC count     \
                                = {1}, Count not MATCHING !!'.format( pd_ns.dynamic_mac_count,                 \
                                pd_dynamic_mac_dict_lc )
                            testResult( 'fail', msg, log )
                        else: 
                            diff = distance( int ( pd_dynamic_mac_dict_lc['dynamic'] ),                        \
                                 int( pd_ns.dynamic_mac_count ) )
                            if int( diff ) > int( pd_ns.threshold ):
                                msg='ERROR !! Expected dynamic PD MAC count = {0}, actual dynamic PD MAC count \
                                 = {1}, Threshold = {2} !!'. format( pd_ns.dynamic_mac_count,                  \
                                 pd_dynamic_mac_dict_lc, pd_ns.threshold )
                                testResult( 'fail', msg, log )


        
            if ns.l3_ipv4_unicast:
                print('Validation for l3_ipv4_unicast')
                pi_ns=parseFwdDictUnicastL3( log, fwd_dict[node]['unicast']['l3']['ipv4']['pi'] )
                pd_ns=parseFwdDictUnicastL3( log, fwd_dict[node]['unicast']['l3']['ipv4']['pd'] )
                
                ## Get the IPv4 route count from the box

                if pi_ns.route_count is not None:
                    pi_total_count=utils.getIpRouteCount( hdl, log, '-vrf all' )
                    if int( pi_total_count ) != int( pi_ns.route_count ):
                        msg='ERROR !! Expected Ipv4 PI count = {0}, Actual Ipv4 PI count = {1} - MISMATCH'.format(   \
                          pi_ns.route_count, pi_total_count )
                        testResult( 'fail', msg, log )
                    else:
                        msg='PASS Expected Ipv4 PI count = {0}, Actual Ipv4 PI count = {1} - MATCHED'.format(        \
                          pi_ns.route_count, pi_total_count )
                        log.info(msg)

                if pi_ns.ospf_count is not None:
                    pi_ospf_count=utils.getIpRouteCount( hdl, log, '-vrf all -protocol ospf' )
                    if int( pi_ospf_count ) != int( pi_ns.ospf_count ):
                        msg='ERROR !! Expected OSPF PI count = {0}, Actual OSPF PI count = {1} - MISMATCH'.format(   \
                          pi_ns.ospf_count, pi_ospf_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected OSPF PI count = {0}, Actual OSPF PI count = {1} - MATCHED'.format(       \
                          pi_ns.route_count, pi_total_count )
                         log.info(msg)

                if pi_ns.bgp_count is not None:
                    pi_bgp_count=utils.getIpRouteCount( hdl, log, '-vrf all -protocol bgp' )
                    if int( pi_bgp_count ) != int( pi_ns.bgp_count ):
                        msg='ERROR !! Expected BGP PI count = {0}, Actual BGP PI count = {1} - MISMATCH'.format(   \
                          pi_ns.bgp_count, pi_bgp_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected BGP PI count = {0}, Actual BGP PI count = {1} - MATCHED'.format(       \
                          pi_ns.bgp_count, pi_bgp_count )
                         log.info(msg)

                if pi_ns.eigrp_count is not None:
                    pi_eigrp_count=utils.getIpRouteCount( hdl, log, '-vrf all -protocol eigrp' )
                    if int( pi_eigrp_count ) != int( pi_ns.eigrp_count ):
                        msg='ERROR !! Expected EIGRP PI count = {0}, Actual EIGRP PI count = {1} - MISMATCH'.format(   \
                          pi_ns.eigrp_count, pi_eigrp_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected EIGRP PI count = {0}, Actual EIGRP PI count = {1} - MATCHED'.format(       \
                          pi_ns.eigrp_count, pi_eigrp_count )
                         log.info(msg)


                if pi_ns.hsrp_count is not None:
                    pi_hsrp_count=utils.getIpRouteCount( hdl, log, '-vrf all -protocol hsrp' )
                    if int( pi_hsrp_count ) != int( pi_ns.hsrp_count ):
                        msg='ERROR !! Expected HSRP PI count = {0}, Actual HSRP PI count = {1} - MISMATCH'.format(   \
                          pi_ns.hsrp_count, pi_hsrp_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected HSRP PI count = {0}, Actual HSRP PI count = {1} - MATCHED'.format(       \
                          pi_ns.hsrp_count, pi_hsrp_count )
                         log.info(msg)

                if pi_ns.vrrp_count is not None:
                    pi_vrrp_count=utils.getIpRouteCount( hdl, log, '-vrf all -protocol vrrp' )
                    if int( pi_vrrp_count ) != int( pi_ns.vrrp_count ):
                        msg='ERROR !! Expected VRRP PI count = {0}, Actual VRRP PI count = {1} - MISMATCH'.format(   \
                          pi_ns.vrrp_count, pi_vrrp_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected VRRP PI count = {0}, Actual VRRP PI count = {1} - MATCHED'.format(       \
                          pi_ns.vrrp_count, pi_vrrp_count )
                         log.info(msg)

            if ns.l3_ipv6_unicast:
                print('Validation for l3_ipv6_unicast')
                pi_ns=parseFwdDictUnicastL3( log, fwd_dict[node]['unicast']['l3']['ipv6']['pi'] )
                pd_ns=parseFwdDictUnicastL3( log, fwd_dict[node]['unicast']['l3']['ipv6']['pd'] )
                
                ## Get the IPv6 route count from the box

                if pi_ns.route_count is not None:
                    pi_total_count=utils.getIpv6RouteCount( hdl, log, '-vrf all' )
                    if int( pi_total_count ) != int( pi_ns.route_count ):
                        msg='ERROR !! Expected Ipv6 PI count = {0}, Actual Ipv6 PI count = {1} - MISMATCH'.format(   \
                          pi_ns.route_count, pi_total_count )
                        testResult( 'fail', msg, log )
                    else:
                        msg='PASS Expected Ipv6 PI count = {0}, Actual Ipv6 PI count = {1} - MATCHED'.format(        \
                          pi_ns.route_count, pi_total_count )
                        log.info(msg)

                if pi_ns.ospfv3_count is not None:
                    pi_ospf_count=utils.getIpv6RouteCount( hdl, log, '-vrf all -protocol ospfv3' )
                    if int( pi_ospf_count ) != int( pi_ns.ospfv3_count ):
                        msg='ERROR !! Expected OSPFv3 IPv6 PI count = {0}, Actual OSPFv3 IPV6 PI count = {1} - MISMATCH'.format(   \
                          pi_ns.ospfv3_count, pi_ospf_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected OSPFv3 IPV6 PI count = {0}, Actual OSPFv3 IPv6 PI count = {1} - MATCHED'.format(       \
                          pi_ns.ospfv3_count, pi_ospf_count )
                         log.info(msg)

                if pi_ns.bgp_count is not None:
                    pi_bgp_count=utils.getIpv6RouteCount( hdl, log, '-vrf all -protocol bgp' )
                    if int( pi_bgp_count ) != int( pi_ns.bgp_count ):
                        msg='ERROR !! Expected BGP IPV6 PI count = {0}, Actual BGP IPV6 PI count = {1} - MISMATCH'.format(   \
                          pi_ns.bgp_count, pi_bgp_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected BGP IPV6 PI count = {0}, Actual BGP IPV6 PI count = {1} - MATCHED'.format(       \
                          pi_ns.bgp_count, pi_bgp_count )
                         log.info(msg)

                if pi_ns.eigrp_count is not None:
                    pi_eigrp_count=utils.getIpv6RouteCount( hdl, log, '-vrf all -protocol eigrp' )
                    if int( pi_eigrp_count ) != int( pi_ns.eigrp_count ):
                        msg='ERROR !! Expected EIGRP IPv6 PI count = {0}, Actual EIGRP IPv6 PI count = {1} - MISMATCH'.format(   \
                          pi_ns.eigrp_count, pi_eigrp_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected EIGRP IPV6 PI count = {0}, Actual EIGRP IPV6 PI count = {1} - MATCHED'.format(       \
                          pi_ns.eigrp_count, pi_eigrp_count )
                         log.info(msg)


                if pi_ns.hsrp_count is not None:
                    pi_hsrp_count=utils.getIpv6RouteCount( hdl, log, '-vrf all -protocol hsrp' )
                    if int( pi_hsrp_count ) != int( pi_ns.hsrp_count ):
                        msg='ERROR !! Expected HSRP IPv6 PI count = {0}, Actual HSRP IPv6 PI count = {1} - MISMATCH'.format(   \
                          pi_ns.hsrp_count, pi_hsrp_count )
                        testResult( 'fail', msg, log )
                    else:
                         msg='PASS Expected HSRP IPv6 PI count = {0}, Actual HSRP IPv6 PI count = {1} - MATCHED'.format(       \
                          pi_ns.hsrp_count, pi_hsrp_count )
                         log.info(msg)

                if pi_ns.vrrp_count is not None:
                    pi_vrrp_count=utils.getIpv6RouteCount( hdl, log, '-vrf all -protocol vrrp' )
                    if int( pi_vrrp_count ) != int( pi_ns.vrrp_count ):
                        msg='ERROR !! Expected VRRP IPv6 PI count = {0}, Actual VRRP IPv6 PI count = {1} - MISMATCH'.format(   \
                          pi_ns.vrrp_count, pi_vrrp_count )
                    else:
                         msg='PASS Expected VRRP IPv6 PI count = {0}, Actual VRRP IPv6 PI count = {1} - MATCHED'.format(       \
                          pi_ns.vrrp_count, pi_vrrp_count )
                         log.info(msg)



            if ns.l2_ipv4_multicast:

                pi_ns=parseFwdDictMulticastL2( log, fwd_dict[node]['multicast']['l2']['pi'] )
                pd_ns=parseFwdDictMulticastL2( log, fwd_dict[node]['multicast']['l2']['pd'] )

                snooping_dict=utils.getIgmpSnoopingGroupsDict( hdl, log )
                omf_dict=utils.getIgmpSnoopingGroupsDict( hdl, log, '-omf_only True' )


                # Verify the igmp snooping counts match..
                if pi_ns.igmp_snooping_group_count is not None:
                    pi_snooping_count=len(snooping_dict.keys())
                    if int( pi_snooping_count ) != int( pi_ns.igmp_snooping_group_count ):
                        msg='ERROR !! MISMATCH in IGMP snooping count. Expected count = {0}, Actual count = {1}'.format(       \
                           pi_ns.igmp_snooping_group_count, pi_snooping_count )
                        testResult( 'fail', msg, log )
                    else:
                        msg='PASS IGMP snooping count MATCHING as expected. Expected count = {0}, Actual count = {1}'.format(  \
                           pi_ns.igmp_snooping_group_count, pi_snooping_count )
                        log.info(msg)

                # Verify the igmp snooping OMF counts match..
                if pi_ns.omf_count is not None:
                    pi_omf_count=len(omf_dict.keys())
                    if int( pi_omf_count ) != int( pi_ns.omf_count ):
                        msg='ERROR !! MISMATCH in IGMP snooping OMF count. Expected count = {0}, Actual count = {1}'.format(   \
                           pi_ns.omf_count, pi_omf_count )
                        testResult( 'fail', msg, log )
                    else:
                        msg='PASS IGMP snooping OMF count MATCHING as expected. Expected count = {0}, Actual count = {1}'.     \
                           format( pi_ns.igmp_snooping_group_count, pi_snooping_count )
                        log.info(msg)








class verifyAllSnmpTrapsEnabled():

    """ 
    verifyAllSnmpTrapsEnabled - Verify if a given SNMP Trap or all SNMP traps are enabled.
    """

    def __init__(self, hdl, log):


        self.result='pass'
        snmp_trap_dict=utils.getShowSnmpTrapDict( hdl, log )
        for snmp_trap in snmp_trap_dict.keys():
            print(snmp_trap_dict[snmp_trap]['Enabled'])
            if re.search( 'No', snmp_trap_dict[snmp_trap]['Enabled'], re.I ):
                testResult( 'fail', 'ERROR !! Snmp Trap {0} not in enabled state'.format( snmp_trap ), log )
            else:
                log.info( 'SNMP Trap {0} in Enabled state as expected'.format(snmp_trap) )

class verifyDir():

    """
    verifydir output of a given file system
    """

    def __init__(self, hdl, log, dirdict, *args):

        self.result='pass'
        arggrammar={}
        arggrammar['option']='-default bootflash: -choices ["bootflash:","debug:", "log:", "logflash:", "usb1:", "usb2:", "volatile:", "bootflash://sup-standby", "logflash://sup-standby", "usb1://sup-standby", "usb2://sup-standby"]'
        arggrammar['files']='-type list'
        arggrammar['negative']='-type bool -default False'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        if not ns.VALIDARGS:
            testResult('fail','arguments to verfiyDir is not correct', log)
            return 

        fileDict=utils.getDir(hdl, log, '-option {0}'.format(ns.option))

        if dirdict:
            if compareVars(dirdict, fileDict, log) == 'pass':
                log.info("{0} exists in {1} - verifyDir for {2} passed".format(dirdict,fileDict,ns.option))
            else:
                testResult('fail',"{0} doesnt exist in {1} - verifyDir for {2} failed".format(dirdict,fileDict,ns.option),log)
            return

        if compareVars(['used','free','total'],fileDict.keys(),log) == 'pass':
            log.info("used,free,total available in {0} - verifyDir for {1} passed".format(fileDict,ns.option))
        else:
            testResult('fail',"used,free,total doesnt exist in {1} - verifyDir for {1} failed".format(fileDict,ns.option),log)

        if ns.files:
            if not ns.negative:
                if compareVars(ns.files,fileDict.keys(),log) == 'pass':
                    log.info("{0} available in {0} - verifyDir for {2} passed".format(ns.files,fileDict,ns.option))
                else:
                    testResult('fail',"{0} doesnt exist in {1} - verifyDir for {2} failed".format(ns.files,fileDict,ns.option),log)
            else:
                if compareVars(ns.files,fileDict.keys(),log) == 'fail':
                    log.info("{0} not available in {0} - verifyDir for {2} passed".format(ns.files,fileDict,ns.option))
                else:
                    testResult('fail',"{0} exist in {1} - verifyDir for {2} failed".format(ns.files,fileDict,ns.option),log)
           
class verifyFormat():

     """
     verify format for given filesystem
     """

     def __init__(self, hdl, log, *args):

         self.result='pass'
         arggrammar={}
         arggrammar['filesystem']='-default bootflash: -choices ["bootflash:", "logflash:", "usb1:", "usb2:"]' 

         ns=parserutils_lib.argsToCommandOptions(args, arggrammar, log)
         if not ns.VALIDARGS:
             testResult('fail','arguments to verifyFormat is not correct', log)
             return

         hdl.hdl.sendline('format {0}'.format(ns.filesystem))
         prompts=['#','yes/no','y/n']
         prompt=hdl.hdl.expect(prompts)
         if prompt == 1:
             hdl.hdl.sendline('yes')
         elif prompt == 2:
             hdl.hdl.sendline('y')

         obj=verifyDir(hdl, log, {}, '-option {0}'.format(ns.filesystem))
         if obj.result == 'fail':
             testResult('fail','verifyDir after format {0} failed'.format(ns.filesystem), log)

class verifyObflcleartime():

    """
    Verify OBFL clear time
    """

    def __init__(self, hdl, log, inputtime, *args):

         self.result = 'pass' 
         arggrammar = {}
         arggrammar['module']='-required true -type int'        
         ns=parserutils_lib.argsToCommandOptions(args, arggrammar, log)
         
         if not ns.VALIDARGS:
             testResult('fail','arguments to verifyObflcleartime is not correct',log)
             return

         cleartime=getObflcleartime(hdl, log, '-module {0}'.format(ns.module))
         if not cleartime:
             testResult('fail','couldnt get obfl clear time for module {0}'.format(ns.module),log)
             return

         months=['','Jan','Feb','Mar','Apr','May','Jun','Jul','Sep','Oct','Nov','Dec']

         time1 = datetime.datetime(int(inputtime['year']),months.index(inputtime['month']),int(inputtime['date']),int(inputtime['time'].split(":")[0]),int(inputtime['time'].split(":")[1]))
         time2 = datetime.datetime(int(cleartime['year']),months.index(cleartime['month']),int(cleartime['date']),int(cleartime['time'].split(":")[0]),int(cleartime['time'].split(":")[1]))

         if time1 > time2:
             testResult('fail','current time {0} is > clear time {1}'.format(inputtime,cleartime),log)
         else:
             log.info('current time {0} is < clear time {1}'.format(inputtime,cleartime))

class verifyModuleResetreason():

     """
     Verify Module reset reason
     """

     def __init__(self,hdl,log,inputtime,*args):

         self.result = 'pass'
         arggrammar = {}
         arggrammar['module'] = '-required true -type int'
         arggrammar['sysresetreason'] = '-default Module is powered down or power cycled'
         arggrammar['obflswreason'] = '-default Unknown'
         arggrammar['obflhwreason'] = '-default NULL'

         ns = parserutils_lib.argsToCommandOptions(args,arggrammar,log)

         if not ns.VALIDARGS:
             testResult('fail', 'arguments to verifyModuleResetreason is not correct', log)
             return

         sysresetreason=getModuleResetReason(hdl, log, '-module {0}'.format(ns.module))
         obflresetreason=getObflResetReason(hdl, log, '-module {0}'.format(ns.module)) 

         if 0 not in sysresetreason.keys() or 0 not in obflresetreason.keys():
              testResult('fail','system reset reason or obfl reset reason is not found for mould {0}'.format(ns.module), log)
              return

         print ("Reason")
         #print obflresetreason        
 
         if 'lcm_reason' not in obflresetreason[0].keys() or 'sw_reason' not in obflresetreason[0].keys() or 'hw_reason' not in obflresetreason[0].keys():
              testResult('fail','OBFL reset reason for modul {0} doesnt have for sw or lcm or hw'.format(ns.module), log)
              return

         if sysresetreason[0]['reason'].strip() != ns.sysresetreason.strip(): 
              testResult('fail','OBFL LCM reset reason for module {0} expected {1} actual {2}'.format(ns.module,ns.sysresetreason,sysresetreason[0]['reason']), log)
              return
             
         if obflresetreason[0]['lcm_reason'][0].strip() != ns.sysresetreason.strip(): 
              testResult('fail','OBFL LCM reset reason for module {0} expected {1} actual {2}'.format(ns.module,ns.sysresetreason,obflresetreason[0]['lcm_reason'][0]), log)
              return

         if obflresetreason[0]['sw_reason'].strip() != ns.obflswreason.strip(): 
              testResult('fail','OBFL SW reset reason for module {0} expected {1} actual {2}'.format(ns.module,ns.obflswreason,obflresetreason[0]['sw_reason']), log)
              return

         if obflresetreason[0]['hw_reason'][0].strip() != ns.obflhwreason.strip(): 
              testResult('fail','OBFL HW reset reason for module {0} expected {1} actual {2}'.format(ns.module,ns.obflhwreason,obflresetreason[0]['hw_reason'][0]), log)
              return

         
         months=['','Jan','Feb','Mar','Apr','May','Jun','Jul','Sep','Oct','Nov','Dec']
         lcm_reason_time=re.findall('([A-Za-z]+)\s+([A-Za-z]+)\s+([0-9]+)\s+([0-9:]+)\s+([0-9]+)',obflresetreason[0]['lcm_reason'][1])
         if len(lcm_reason_time) != 1 or len(lcm_reason_time[0]) != 5:
              testResult('fail','OBFL lcm reset reason couldnt be read',log)
         else:
              time1 = datetime.datetime(int(inputtime['year']),months.index(inputtime['month']),int(inputtime['date']),int(inputtime['time'].split(":")[0]),int(inputtime['time'].split(":")[1]))
              time2 = datetime.datetime(int(lcm_reason_time[0][4]),months.index(lcm_reason_time[0][1]),int(lcm_reason_time[0][2]),int(lcm_reason_time[0][3].split(":")[0]),int(lcm_reason_time[0][3].split(":")[1]),int(lcm_reason_time[0][3].split(":")[2]))
              if time1 < time2:
                  log.info("lcm reset reason time is after stimuli")
              else:
                  testResult('fail','lcm reset reason time is not after stimuli stimuli done at {0} lcm_reset_reason {1}'.format(time1,time2),log)
                  return

         hw_reason_time=re.findall('([A-Za-z]+)\s+([A-Za-z]+)\s+([0-9]+)\s+([0-9:]+)\s+([0-9]+)',obflresetreason[0]['hw_reason'][1])
         if len(hw_reason_time) != 1 or len(hw_reason_time[0]) != 5:
              testResult('fail','OBFL hw reset reason couldnt be read',log)
         else:
              time1 = datetime.datetime(int(inputtime['year']),months.index(inputtime['month']),int(inputtime['date']),int(inputtime['time'].split(":")[0]),int(inputtime['time'].split(":")[1]))
              time2 = datetime.datetime(int(hw_reason_time[0][4]),months.index(lcm_reason_time[0][1]),int(lcm_reason_time[0][2]),int(lcm_reason_time[0][3].split(":")[0]),int(lcm_reason_time[0][3].split(":")[1]),int(lcm_reason_time[0][3].split(":")[2]))
              if time1 < time2:
                  log.info("hw reset reason time is after stimuli")
              else:
                  testResult('fail','hw reset reason time is not after stimuli stimuli done at {0} lcm_reset_reason {1}'.format(time1,time2),log)
                  return

         sysreset_reason_time=re.findall('([A-Za-z]+)\s+([A-Za-z]+)\s+([0-9]+)\s+([0-9:]+)\s+([0-9]+)',sysresetreason[0]['time'])
         if len(sysreset_reason_time) != 1 or len(sysreset_reason_time[0]) != 5:
              testResult('fail','OBFL sysreset reset reason couldnt be read',log)
         else:
              time1 = datetime.datetime(int(inputtime['year']),months.index(inputtime['month']),int(inputtime['date']),int(inputtime['time'].split(":")[0]),int(inputtime['time'].split(":")[1]))
              time2 = datetime.datetime(int(sysreset_reason_time[0][4]),months.index(lcm_reason_time[0][1]),int(lcm_reason_time[0][2]),int(lcm_reason_time[0][3].split(":")[0]),int(lcm_reason_time[0][3].split(":")[1]),int(lcm_reason_time[0][3].split(":")[2]))
              if time1 < time2:
                  log.info("sysreset reset reason time is after stimuli")
              else:
                  testResult('fail','sysreset reset reason time is not after stimuli stimuli done at {0} lcm_reset_reason {1}'.format(time1,time2),log)
                  return
         
###################################################################

class verifyBfdInterfaceInterval():
    '''
    # Sample Usage:
    # verification will be done against a bfd_config_dict
    # verifyBfdInterfaceInterval(hdl,log)
    '''

    def __init__(self,log,hlite,switch_hdl_dict):
        self.result='pass'
        arggrammar={}
        arggrammar['min_tx']='-type int'
        arggrammar['min_rx']='-type int'
        arggrammar['interval_multiplier']='-type int'

        self.switch_hdl_dict=switch_hdl_dict
        self.bfd_config_dict=hlite.gd['Topology']['bfd_config_dict']
        log.info('Bfd_dict: {0}'.format(self.bfd_config_dict))
        
        for node in self.bfd_config_dict:
          self.result='pass'
          log.info('Node: {0}'.format(node))
          hdl=self.switch_hdl_dict[node]
          log.info('hdl.switchName: {0}'.format(hdl.switchName))
          for config in self.bfd_config_dict[node].keys():
            if 'global_configs' in self.bfd_config_dict[node].keys():
              log.info('Global Level BFD Interval Verification...')
              bfd_global_dict=hlite.gd['Topology']['bfd_config_dict'][node]['global_configs']
              parseoutput = parserutils_lib.argsToCommandOptions(bfd_global_dict,arggrammar,None)
              minTx=parseoutput.min_tx
              minRx=parseoutput.min_rx
              multiplier=parseoutput.interval_multiplier
              log.info('TopoMinTx: {0}, TopoMinRx: {1}, TopoMultiplier: {2}'.format(minTx,minRx,multiplier))

              # Get the output from switch
              out_bfd_intf_interval = utils.getBfdGlobalInterval(hdl,log)
              swMinTx=out_bfd_intf_interval[0]
              swMinRx=out_bfd_intf_interval[1]
              swMultiplier=out_bfd_intf_interval[2]
              log.info('swMinTx: {0}, swMinRx: {1}, swMultiplier: {2}'.format(swMinTx,swMinRx,swMultiplier))

              # Verify Bfd intervals for Interface
              if not (minTx and minRx and multiplier):
                log.info('Insufficient parameters passed to verifyBfdInterfaceInterval')
                self.result='fail'
              else :
                if int( minTx ) != int( swMinTx ):
                  log.error('Global Bfd minTx {0} is not configured properly for Switch {1}'.format(minTx,hdl.switchName))
                  self.result='fail'
                  break
                if int( minRx ) != int( swMinRx ):
                  log.error('Global Bfd minRx {0} is not configured properly for Switch {1}'.format(minRx,hdl.switchName))
                  self.result='fail'
                  break
                if int( multiplier ) != int( swMultiplier ):
                  log.error('Global Bfd multiplier {0} is not configured properly for Switch {1}'.format(multiplier,hdl.switchName))
                  self.result='fail'
                  break

            if 'interface_configs' in self.bfd_config_dict[node].keys():
              log.info('Interface Level BFD Interval Verification...')
              log.info('Intf_list: {0}'.format(self.bfd_config_dict[node]['interface_configs'].keys()))
              log.info('Node: {0}, hdl: {1}'.format(node,hdl))
              for intf in self.bfd_config_dict[node]['interface_configs'].keys():
                log.info('Intf: {0}'.format(intf))
                bfd_dict=hlite.gd['Topology']['bfd_config_dict'][node]['interface_configs'][intf]
                log.info('bfd_dict: {0}'.format(bfd_dict))
                parseoutput = parserutils_lib.argsToCommandOptions(bfd_dict,arggrammar,None)
                minTx=parseoutput.min_tx
                minRx=parseoutput.min_rx
                multiplier=parseoutput.interval_multiplier
                log.info('TopoMinTx: {0}, TopoMinRx: {1}, TopoMultiplier: {2}'.format(minTx,minRx,multiplier))

                # Get the output from switch
                out_bfd_intf_interval = utils.getBfdInterfaceInterval(hdl,intf,log)
                if out_bfd_intf_interval == 0:
                  log.error('Bfd Intervals are not configured for interface {0} on switch {1}'.format(intf,hdl.switchName))
                  self.result='fail'
                  break
                else:
                  swMinTx=out_bfd_intf_interval[0]
                  swMinRx=out_bfd_intf_interval[1]
                  swMultiplier=out_bfd_intf_interval[2]
                  log.info('swMinTx: {0}, swMinRx: {1}, swMultiplier: {2}'.format(swMinTx,swMinRx,swMultiplier))
  
                  # Verify Bfd intervals for Interface
                  if not (minTx and minRx and multiplier):
                    log.info('Insufficient parameters passed to verifyBfdInterfaceInterval')
                    self.result='fail'
                  else :
                    if int( minTx ) != int( swMinTx ):
                      log.error('Bfd minTx {0} is not configured properly for interface {1}'.format(minTx,intf))
                      self.result='fail'
                      break
                    if int( minRx ) != int( swMinRx ):
                      log.error('Bfd minRx {0} is not configured properly for interface {1}'.format(minRx,intf))
                      self.result='fail'
                      break
                    if int( multiplier ) != int( swMultiplier ):
                      log.error('Bfd multiplier {0} is not configured properly for interface {1}'.format(multiplier,intf))
                      self.result='fail'
                      break

        # Set the final result
        if self.result =='pass':
          testResult('pass','Bfd Interval verification passed on {0}'.format(hdl.switchName), log)
        else:
          testResult('fail','Bfd Interval verification failed on {0}'.format(hdl.switchName), log)


class verifyBfdNeighbor():
    '''
    # Sample Usage:
    # verification will be done against a nei_dict key or per interface,nbr and ourAddr details
    # verifyBfdNeighbor(hdl,log)
    # verifyBfdNeighbor(hdl,log, '-vrf default -OurAddr 10.1.1.1 -neighbor 10.1.1.2 -intf Eth2/1')
    # nei_dict={}
    # nei_dict['11.4.10.1','Eth8/10']={}
    # nei_dict['11.4.10.1','Eth8/10']['State']='Up'
    # nei_dict['11.4.10.1','Eth8/10']['OurAddr']='11.4.10.0'
    # nei_dict['11.4.30.1','Eth8/30']={}
    # nei_dict['11.4.30.1','Eth8/30']['State']='Up'
    # verifyBfdNeighbor(hdl,log, bfd_dict=nei_dict)
    '''

    def __init__(self,hdl, log, *args, **nei_dict):        
        self.result='pass'
        arggrammar={}
        arggrammar['vrf']='-type str'
        arggrammar['OurAddr']='-type str'
        arggrammar['neighbor']='-type str'
        arggrammar['intf']='-type str'
        arggrammar['iteration']='-type int -default 1'
        arggrammar['interval']='-type int -default 30'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        if parse_output.intf:
            parse_output.intf=normalizeInterfaceName(log,parse_output.intf)
        for loop in range(parse_output.iteration):
            log.info ('Starting loop : {0} in verifyBfdNeighbor'.format(loop))
            loopuntil_result='pass'  
            # Get the actual output from switch
            if parse_output.vrf:
                out_bfd_dict = utils.getBfdNeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
            else:
                out_bfd_dict = utils.getBfdNeighborDict(hdl,log)
            # All verification steps as below
            if nei_dict:
                bfd_dict=nei_dict['bfd_dict']
                # The values from this dictionary will be verified against the values from get proc
                for nei_key in bfd_dict.keys():
                    if (nei_key not in out_bfd_dict.keys()):
                        log.info('Attempt {0} of {1} - No Info for BFD Neighbor:{2}'.\
                                     format(loop, parse_output.iteration, nei_key))
                        loopuntil_result='fail'
                    # Check the interface and Status as up
                    elif (out_bfd_dict[nei_key]['State'] != 'Up'):
                        log.info('Attempt {0} of {1} - Status not Up for neighbor: {2},State=:{3}:'.\
                                     format(loop, parse_output.iteration,nei_key,out_bfd_dict[nei_key]['State']))
                        loopuntil_result='fail'
                    elif 'OurAddr' in bfd_dict[nei_key].keys():
                        if (out_bfd_dict[nei_key]['OurAddr'] != bfd_dict[nei_key]['OurAddr']):
                            log.info('Attempt {0} of {1} - Our Addr not same for neighbor: {2},Exptected:{3}, Found:{4}'.\
                                         format(loop, parse_output.iteration,nei_key,bfd_dict[nei_key]['OurAddr'],\
                                                    out_bfd_dict[nei_key]['OurAddr']))
                            loopuntil_result='fail'
            # Verify neighbor is in Up State
            if parse_output.neighbor or parse_output.intf or parse_output.OurAddr:
                if not (parse_output.neighbor and parse_output.intf and parse_output.OurAddr):
                    log.info('Insufficient parameters passed to verifyBfdNeighbors')
                    self.result='fail'
                    break
                nei_key = parse_output.neighbor,parse_output.intf
                if (nei_key not in out_bfd_dict.keys()):
                    log.info('Attempt {0} of {1} - No Info for BFD Neighbor:{2}'.\
                                 format(loop, parse_output.iteration, nei_key))
                    loopuntil_result='fail'
                elif (out_bfd_dict[nei_key]['State'] != 'Up'):
                    log.info('Attempt {0} of {1} - State not Up for neighbor: {2}'.\
                                 format(loop,parse_output.iteration,nei_key[0]))
                    loopuntil_result='fail'
                elif (parse_output.OurAddr != out_bfd_dict[nei_key]['OurAddr']):
                    log.info('Attempt {0} of {1} - Our Addr not same for neighbor: {2},Exptected:{3}, Found:{4}'.\
                                 format(loop, parse_output.iteration,nei_key,parse_output.OurAddr,\
                                            out_bfd_dict[nei_key]['OurAddr']))
                    loopuntil_result='fail'
            if not nei_dict and not parse_output.neighbor and not parse_output.intf and not parse_output.OurAddr:
                for nei_key in out_bfd_dict.keys():
                    if (out_bfd_dict[nei_key]['State'] != 'Up'):
                        log.info('Attempt {0} of {1} - Status not Up for neighbor: {2},State=:{3}:'.\
                                     format(loop, parse_output.iteration,nei_key,out_bfd_dict[nei_key]['State']))
                        loopuntil_result='fail'
            if loopuntil_result=='pass':
                break
            if loop==parse_output.iteration-1:
                self.result='fail'
            else:
                log.info ('Wait for {0} sec for next iteration'.format(parse_output.interval))
                time.sleep(parse_output.interval)
        # Set the final result
        if loopuntil_result=='pass' and self.result =='pass':
            testResult('pass','Bfd Neighbor verification passed on {0}'.format(hdl.switchName), log)
        else:
            testResult('fail','Bfd Neighbor verification failed on {0}'.format(hdl.switchName), log)

class verifyEigrpNeighbor():

  def __init__(self,hdl, log, *args, **eigrp_dict):
    self.result='pass'

    # Sample Usage:
    # verifyEigrpNeighbor(hdl,log)
    # verifyEigrpNeighbor(hdl,log, '-vrf default')
    # verifyEigrpNeighbor(hdl,log, neighbor_list)
    # verifyEigrpNeighbor(hdl,log, **neighbor_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbors']='-type str'
    arggrammar['iteration']='-type int -default 1'
    arggrammar['interval']='-type int -default 30'

    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
    
    for loop in range(parse_output.iteration):
        loopuntil_result='pass'  
    
        # Get the actual output from switch
        if parse_output.vrf:
            out_eigrp_dict = getEigrpNeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
        else:
            out_eigrp_dict = getEigrpNeighborDict(hdl,log)
        if parse_output.neighbors:
            neighbors=re.findall('('+rex.IPv4_ADDR+')',parse_output.neighbors)
        else:
            neighbors = []
        # All verification steps as below
        if eigrp_dict:
            # The values from this dictionary will be verified against the values from get proc
            for nei in eigrp_dict.keys():
                if (nei not in out_ospf_dict.keys()):
                    log.info('Attempt {0} of {1} - No Info for Eigrp Neighbor:{2} on {3}'.\
                                    format(loop, parse_output.iteration, nei,out_eigrp_dict[nei]['Interface']))
                    loopuntil_result='fail'
                    continue
                # Check Expected keys are in output keys , return fail if it's not,
                # check following lines otherwise
                for key in eigrp_dict[nei].keys():
                    if key not in out_eigrp_dict[nei].keys():
                        log.info('Attempt {0} of {1} - No Info for key:({2}) for eigrp Neighbor {3}'.\
                                        format(loop, parse_output.iteration, key,nei))
                        loopuntil_result='fail'
                        continue
                    #To Do exact match
                    if (eigrp_dict[nei][key] == out_eigrp_dict[nei][key]):
                        log.info('Eigrp Neighbor:{0} has value {1} for {2}'.\
                                        format(nei,out_eigrp_dict[nei][key],key))
                    else:
                        log.info('Attempt {0} of {1} - Eigrp Neighbor:{2} has value {3} for {4}'.\
                                        format(loop, parse_output.iteration, nei,out_eigrp_dict[nei][key],key))
                        loopuntil_result='fail'

        if neighbors:
            # Neighbors will be tested in this section to make sure they are in adjacent state
            for nei in neighbors:
                if (nei not in  out_eigrp_dict.keys()):
                    # If this is not in output then fail cases
                    log.info('Attempt {0} of {1} - EIGRP Neighbor:{2} NOT in EIGRP neighbor list'.format(loop, parse_output.iteration, nei))
                    loopuntil_result='fail'
                else:
                    # Go through list of all neighbors and print the uptime for the neighbor
                    log.info('Eigrp Neighbor:{0} Up since {1}'.\
                                    format(nei,out_eigrp_dict[nei]['Up_Time']))

        if loopuntil_result=='pass':
            break
        if loop==parse_output.iteration-1:
            self.result='fail'
        else:
            time.sleep(parse_output.interval)

    if self.result=='pass':
        testResult('pass','Eigrp Neighbor verification passed on {0}'.format(hdl.switchName), log)
    else:
        testResult('fail','Eigrp Neighbor verification failed on {0}'.format(hdl.switchName), log)


class verifyEigrpv6Neighbor():

  def __init__(self,hdl, log, *args, **eigrpv6_dict):
    self.result='pass'

    # Sample Usage:
    # verifyEigrpv6Neighbor(hdl,log)
    # verifyEigrpv6Neighbor(hdl,log, '-vrf default')
    # verifyEigrpv6Neighbor(hdl,log, interface_list)
    # verifyEigrpv6Neighbor(hdl,log, **interface_dict)

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['interface']='-type str'
    arggrammar['iteration']='-type int -default 1'
    arggrammar['interval']='-type int -default 30'

    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    for loop in range(parse_output.iteration):
        loopuntil_result='pass'  
    
        # Get the actual output from switch
        if parse_output.vrf:
            out_eigrpv6_dict = getEigrpv6NeighborDict(hdl,log,'-vrf ' + parse_output.vrf)
        else:
            out_eigrpv6_dict = getEigrpv6NeighborDict(hdl,log)
        if parse_output.interface:
            interface=re.findall('('+rex.INTERFACE_NAME+')',parse_output.interface)
            intf=listtostr(interface)
            intf=normalizeInterfaceName(log,intf)
        else:
            interface = []

        # All verification steps as below
        if eigrpv6_dict:
            eigrpv6_dict = eigrpv6_dict['value']
            # The values from this dictionary will be verified against the values from get proc
            for intf in eigrpv6_dict.keys():
                if (intf not in out_eigrpv6_dict.keys()):
                    testResult('fail','No Info for Ipv6 EIGRP Interface:{0}'.\
                                    format(intf),log)
                    loopuntil_result='fail'
                    continue
                # Check Expected keys are in output keys , return fail if it's not,
                # check following lines otherwise
                for key in eigrpv6_dict[intf].keys():
                    if key not in out_eigrpv6_dict[intf].keys():
                        testResult('fail','No Info for Ipv6 EIGRP Interface {0}'.\
                                        format(intf),log)
                        loopuntil_result='fail'
                        continue
                    #To Do exact match
                    if (eigrpv6_dict[intf][key] == out_eigrpv6_dict[intf][key]):
                        testResult('pass','Ipv6 EIGRP Interface:{0} has value {1} for {2}'.\
                                        format(intf,out_eigrpv6_dict[intf][key],key),log)
                    else:
                        testResult('fail','Ipv6 EIGRP Interface:{0} has value {1} for {2}'.\
                                        format(intf,out_eigrpv6_dict[intf][key],key),log)
                        loopuntil_result='fail'
        if interface:
            # Neighbors will be tested in this section to make sure they are in FULL state
                keys = getKeys(intf,out_eigrpv6_dict.keys())
                if not keys:
                    testResult('fail','Interface {0} not in eigrpv6 neighbor dict on {1}'.format(intf, hdl.switchName), log)
                    loopuntil_result='fail'
                for key in keys:
                    testResult('pass','Ipv6 EIGRP Interface:{0} adjacency is Up'.\
                                  format(key),log)
        if loopuntil_result=='pass':
            break
        if loop==parse_output.iteration-1:
            self.result='fail'
        else:
            time.sleep(parse_output.interval)


    if self.result=='pass':
        testResult('pass','Eigrp Neighbor verification passed on {0}'.format(hdl.switchName), log)
    else:
        testResult('fail','Eigrp Neighbor verification failed on {0}'.format(hdl.switchName), log)


############################
class verifySystemRoutingMode():
  "  verifySystemRoutingMode - Method to verify system routing mode\
  \
  Mandatory Args\
  \
  hdl - icon switch object\
  log - harness/python logger object\
  mode - max-host, non-hier or default \
  \
  Usage\
  \
  verifySystemRoutingMode( hdl, log, '-mode max-host' )\
  \ "
  def __init__(self, hdl, log, *args ):
     self.result='pass'

     arggrammar={}
     arggrammar['mode']='-type str -required True -choices ["max-host","non-hier","default"]'
     ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

     ## Verification done using 'show run', until cli available for routing mode
     running_config = utils.getRunningConfig(hdl, log)
     if ns.mode == 'max-host':
         if "system routing max-mode host" not in running_config:
             utils.testResult('fail','Switch {0} not in max-host mode after reload'.format(hdl.switchName), log)
         else:
             utils.testResult('pass','Switch {0} is in max-host mode after reload'.format(hdl.switchName), log)
     elif ns.mode == 'non-hier':
         if "system routing non-hierarchical max-mode l3" not in running_config:
             utils.testResult('fail','Switch {0} not in non-hierarchical max l3 mode after reload'.format(hdl.switchName), log)
         else:
             utils.testResult('pass','Switch {0} is in non-hierarchical l3  mode after reload'.format(hdl.switchName), log)
     elif ns.mode == 'default':
         if "system routing max-mode host" in running_config or "system routing non-hierarchical max-mode l3" in running_config:
             utils.testResult('fail','Switch {0} not in default mode after reload'.format(hdl.switchName), log)
         else:
             utils.testResult('pass','Switch {0} is in default after reload'.format(hdl.switchName), log)

'''
class verifyFabricConnectivity():

    def __init__(self, hdl, log, *args):

        self.result='pass'

        ModuleInfo={}
        ModuleInfo['N9K-X9564PX']={}
        ModuleInfo['N9K-X9564PX']['Asics']={}
        ModuleInfo['N9K-X9564PX']['Asics']['T2']=2
        ModuleInfo['N9K-X9564PX']['Asics']['NS']=2
        ModuleInfo['N9K-X9564PX']['Fabricconnectivity']={}
        ModuleInfo['N9K-X9564PX']['Fabricconnectivity']['Asics']='NS'
        ModuleInfo['N9K-X9564PX']['Fabricconnectivity']['Links']=12
        ModuleInfo['N9K-X9564PX']['Fabricconnectivity']['Hgnumbering']='decreasing'
        ModuleInfo['N9K-X9564PX']['Fabricconnectivity']['Mux']='EventoOdd'
        
        ModuleInfo['N9K-X9564TX']={}
        ModuleInfo['N9K-X9564TX']['Asics']={}
        ModuleInfo['N9K-X9564TX']['Asics']['T2']=2
        ModuleInfo['N9K-X9564TX']['Asics']['NS']=2
        ModuleInfo['N9K-X9564TX']['Fabricconnectivity']={}
        ModuleInfo['N9K-X9564TX']['Fabricconnectivity']['Asics']='NS'
        ModuleInfo['N9K-X9564TX']['Fabricconnectivity']['Links']=12
        ModuleInfo['N9K-X9564TX']['Fabricconnectivity']['Hgnumbering']='decreasing'
        ModuleInfo['N9K-X9564TX']['Fabricconnectivity']['Mux']='EventoOdd'
        
        ModuleInfo['N9K-X9636PQ']={}
        ModuleInfo['N9K-X9636PQ']['Asics']={}
        ModuleInfo['N9K-X9636PQ']['Asics']['T2']=3
        ModuleInfo['N9K-X9636PQ']['Fabricconnectivity']={}
        ModuleInfo['N9K-X9636PQ']['Fabricconnectivity']['Asics']='T2'
        ModuleInfo['N9K-X9636PQ']['Fabricconnectivity']['Links']=12
        ModuleInfo['N9K-X9636PQ']['Fabricconnectivity']['Hgnumbering']='increasing'
        
        ModuleInfo['N9K-C9504-FM']={}
        ModuleInfo['N9K-C9504-FM']['Asics']={}
        ModuleInfo['N9K-C9504-FM']['Asics']['T2']=1
        ModuleInfo['N9K-C9504-FM']['Fabricconnectivity']={}
        ModuleInfo['N9K-C9504-FM']['Fabricconnectivity']['Asics']='T2'
        ModuleInfo['N9K-C9504-FM']['Fabricconnectivity']['Links']=24
        ModuleInfo['N9K-C9504-FM']['Fabricconnectivity']['LinkstoeachLC']=6
        
        ModuleInfo['N9K-C9508-FM']={}
        ModuleInfo['N9K-C9508-FM']['Asics']={}
        ModuleInfo['N9K-C9508-FM']['Asics']['T2']=2
        ModuleInfo['N9K-C9508-FM']['Fabricconnectivity']={}
        ModuleInfo['N9K-C9508-FM']['Fabricconnectivity']['Asics']='T2'
        ModuleInfo['N9K-C9508-FM']['Fabricconnectivity']['Links']=24
        ModuleInfo['N9K-C9508-FM']['Fabricconnectivity']['LinkstoeachLC']=3
       
        fcdict=utils.getFabricCardDict(hdl,log) 
        lcdict=utils.getLineCardDict(hdl,log) 
        fms=fcdict.keys()
        actualhgdict={}
        expectedhgdict={}
        
        for lc in lcdict.keys():
            actualhgdict[lc]=utils.getFabricConnectivity(hdl,log,'-module {0}'.format(lc))
            lcmodel=lcdict[lc]['Model']
            expectedhgdict[lc]=collections.OrderedDict()
            curfmunit=0
            for lcunit in range(ModuleInfo[lcdict[lc]['Model']]['Asics'][ModuleInfo[lcdict[lc]['Model']]['Fabricconnectivity']['Asics']]):
                expectedhgdict[lc][str(lcunit)]=collections.OrderedDict()
                if ModuleInfo[lcdict[lc]['Model']]['Fabricconnectivity']['Hgnumbering'] == 'increasing':
                     curfm=21
                     fmincr=1
                elif ModuleInfo[lcdict[lc]['Model']]['Fabricconnectivity']['Hgnumbering'] == 'decreasing':
                     curfm=26
                     fmincr=-1
                incrementfactor=0
                for hglink in range(ModuleInfo[lcdict[lc]['Model']]['Fabricconnectivity']['Links']):
                    if str(curfm) in fcdict.keys() and fcdict[str(curfm)]['Status'] == 'ok':
                        expectedhgdict[lc][str(lcunit)]['HG'+'%02d' % hglink]=collections.OrderedDict()
                        expectedhgdict[lc][str(lcunit)]['HG'+'%02d' % hglink][str(curfm)]=collections.OrderedDict()                
                        expectedhgdict[lc][str(lcunit)]['HG'+'%02d' % hglink][str(curfm)][str(curfmunit)]='HG'+'%02d' % ((int(lc)-1)*ModuleInfo[fcdict[str(curfm)]['Model']]['Fabricconnectivity']['LinkstoeachLC']+lcunit+incrementfactor)
                    curfmunit=curfmunit+1
                    if curfmunit == ModuleInfo[fcdict[str(curfm)]['Model']]['Asics']['T2']:
                        if incrementfactor == 3 or fcdict[str(curfm)]['Model'] == 'N9K-C9508-FM':
                            if lcunit == 0 and 'Mux' in ModuleInfo[lcdict[lc]['Model']]['Fabricconnectivity'].keys() and curfm in [22,24,26] \
                                and (str(curfm+fmincr) not in fcdict.keys() or (str(curfm+fmincr) in fcdict.keys() and fcdict[str(curfm+fmincr)]['Status'] != 'ok')):
                                incrementfactor=2
                                curfmunit=0                        
                            else:
                                incrementfactor = 0
                                curfmunit=0
                                curfm=curfm+fmincr
                        elif not incrementfactor and fcdict[str(curfm)]['Model'] == 'N9K-C9504-FM':
                            incrementfactor=3 
                            curfmunit=0
                        elif incrementfactor == 2 and fcdict[str(curfm)]['Model'] == 'N9K-C9504-FM':
                            incrementfactor=5
                            curfmunit=0
                        elif incrementfactor == 2 and fcdict[str(curfm)]['Model'] == 'N9K-C9508-FM':
                            curfm=curfm+fmincr+fmincr
                            incrementfactor=0
                            curfmunit=0
                        elif incrementfactor == 5:
                            curfm=curfm+fmincr+fmincr
                            incrementfactor=0
                            curfmunit=0
                        else:
                            curfm=curfm+fmincr
                            incrementfactor=0
                            curfmunit=0
        
        if utils.compareVars(expectedhgdict,actualhgdict,log) == 'fail':
            testResult('fail','hg link connectivity verification failed expected {0} actual {1}'.format(expectedhgdict,actualhgdict),log)
        else:
            log.info('hg link connectivity verification passed') 

        for lc in lcdict.keys():
            for lcunit in range(ModuleInfo[lcdict[lc]['Model']]['Asics'][ModuleInfo[lcdict[lc]['Model']]['Fabricconnectivity']['Asics']]):
                psdict=bcm_utils.getBcmPsDict(hdl,log,'-module {0} -unit {1} -port hg'.format(lc,lcunit))
                for hglink in psdict.keys():
                    if 'HG'+'%02d' % int(hglink[2:]) in expectedhgdict[lc][str(lcunit)].keys():
                        if psdict[hglink]['status'].strip() != 'up':
                            log.error('{0} on lc {1} unit {2} is expected to be up but down'.format(hglink,lc,lcunit))
                            self.result = 'fail'
                    elif psdict[hglink]['status'] != '!ena':
                        log.error('{0} on lc {1} unit {2} is expected not to be enabled'.format(hglink,lc,lcunit))
                        self.result = 'fail'
                trunkdict=bcm_utils.getBcmTrunkShowDict(hdl,log,'-module {0} -unit {1}'.format(lc,lcunit))
                

        for fm in fcdict.keys():
            for fmunit in range(ModuleInfo[fcdict[fm]['Model']]['Asics'][ModuleInfo[fcdict[fm]['Model']]['Fabricconnectivity']['Asics']]):
                psdict=bcm_utils.getBcmPsDict(hdl,log,'-module {0} -unit {1}'.format(fm,fmunit))
                trunkdict=bcm_utils.getBcmTrunkShowDict(hdl,log,'-module {0} -unit {1}'.format(fm,fmunit))
            
'''
        
class verifyLicense():
    ''' verifyLicense - Method to verify if license is enabled or not
        Mandatory Args:
        hdl - handle of the switch 
        log - harness/python logger object
        feature - license feature
        Usage:
        verifyLicense(hdl,log, '-feature LAN_ENTERPRISE_SERVICES_PKG')
    '''
    def __init__ (self, hdl, log, *args):
        self.result='pass'
        arggrammar={}
        arggrammar['feature']='-type str -default LAN_ENTERPRISE_SERVICES_PKG'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        
        license=utils.getLicenseUsage(hdl,log)
        if license['Ins'] == "Yes" and license['Feature'] == ns.feature:
                testResult( 'pass','License {0} is installed on the DUT'.format(ns.feature),log)
        else:
                testResult( 'fail','License {0} is not installed on the DUT'.format(ns.feature),log)
                
class verifyLicenseApp():
    ''' verifyLicenseApp - Method to verify which features are using the license
        Mandatory Args:
        hdl - handle of the switch 
        log - harness/python logger object
        feature - license feature
        protocols - protocols using the license
        Usage:
        verifyLicenseApp(hdl,log, '-feature LAN_ENTERPRISE_SERVICES_PKG -protocol bgp')
    '''
    def __init__ (self, hdl, log, protoList, *args):
        arggrammar={}
        arggrammar['feature']='-default LAN_ENTERPRISE_SERVICES_PKG'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.proto=protoList
        self.result='pass'
        resList=utils.getLicenseApp(hdl,log, '-feature {0}'.format(ns.feature))
        resStr=listtostr(resList)
        for list in self.proto:
            comp = re.search(list,resStr)    
            if not comp:
                self.result='fail'    
        if self.result:
                testResult( 'pass','protocols are using the license',log)        
        else:
                testResult( 'pass','protocols are using the license',log)    


def verifyNoSpanningTreeForL3Port(hlite,log,hdl,interface):
        #print interface
        log.info('Interface is {0}'.format(interface))
        show_interface_log=hdl.iexec('show spanning-tree interface {0}'.format(interface))
        pattern = 'No spanning tree information available for {0}'.format(interface)
        process_log_list = re.findall(pattern,show_interface_log)
        if not process_log_list:
            utils.testResult ('pass', 'No Spanning tree on L3  interface {1}  found on switch  {0}'.format(hdl.switchName,interface),log)
        else:
            utils.testResult ('fail','Spanning tree enabled on L3 interface {1}  seen on {0}'.format(hdl.switchName,interface),log)


class returnInterfaceStatus():
  "  To verify all or given set of interfaces are in given status\
  Usage: returnInterfaceStatus(hdl,log,'-status up')\
verifyInterfacesAreUp(hdl,log,'status up -interfaces Eth3/13-20')"
  def __init__(self,hdl,log,*args):
   self.result='pass'

   arggrammar={}
   arggrammar['interfaces']='-type str -default all'
   arggrammar['iteration']='-type int -default 1'
   arggrammar['interval']='-type int -default 30'
   arggrammar['status']='-type str -choices ["up","down","err-disabled","err-vlans","inactive"] -default "up"'

   ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
   ns.status=ns.status.strip("'")
   ns.status=ns.status.strip('"')

   interfaces=listtostr(strtoexpandedlist(ns.interfaces))
   for iteration in range(ns.iteration):
       result=True
       if ns.status in ['up','down']:
           self.intdict=getInterfaceBriefDict(hdl,log,'-interface {0}'.format(interfaces))
           intstatusdict={}
           for interface in self.intdict:
               interface=normalizeInterfaceName(log,interface)
               if self.intdict[interface]['Status'] == ns.status:
                   intstatusdict[interface]=self.intdict[interface]
                   log.info ('status of interface {0} is {1}'.format(interface, self.intdict[interface]['Status']))
               else:
                   log.info('status of interface {0} is {1} {2}'.format(interface, self.intdict[interface]['Status'], self.intdict[interface]['Reason'])) 
                   self.result = 'fail'           
        #return 'intdict.interface.status intdict.interface.reason'
                   #testResult ( 'fail', 'inteface {0} status {1} failed with reason {2}'.format(interface, intdict[interface]['Status'], intdict[interface]['Reason']),log)
