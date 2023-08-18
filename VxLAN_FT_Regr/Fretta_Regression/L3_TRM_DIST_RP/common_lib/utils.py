# Best Pratices for get() functions:
# 1. Use class rex as much as possible for standard regular expressions
# 2. Use underscore in keys wherever white-space appears in the output header
# 3. Add author name, description of function, sample usage examples and return value
# 4. Use python documentation format for #3 above, so that the documentation for all the functions can be pulled out easily

import yaml
import os
import getpass
import sys
import copy
from copy import deepcopy
import re
import random
import time
import logging
import collections
import inspect
import parserutils_lib
import threading
import bisect
import struct
import socket
import ipaddr
import netaddr

MASKS=['0.0.0.0','128.0.0.0','192.0.0.0','224.0.0.0','240.0.0.0','248.0.0.0','252.0.0.0','254.0.0.0','255.0.0.0','255.128.0.0','255.192.0.0','255.224.0.0','255.240.0.0','255.248.0.0','255.252.0.0', '255.254.0.0', '255.255.0.0', '255.255.128.0', '255.255.192.0', '255.255.224.0', '255.255.240.0', '255.255.248.0', '255.255.252.0', '255.255.254.0', '255.255.255.0', '255.255.255.128', '255.255.255.192', '255.255.255.224', '255.255.255.240', '255.255.255.248', '255.255.255.252', '255.255.255.254', '255.255.255.255']
   

class rex:
   INTERFACE_TYPE="[Ff]ast[Ee]thernet|[Ff][Ee]th|[Gg]igabit[Ee]thernet|[Gg]ig[Ee]|[Ee]thernet|[Ee]th|[Tt]unnel ?|[Ll]oopback ?|[Pp]ort-channel ?|[Oo]verlay ?|[Nn]ull|[Mm]gmt|[Vv]lan ?|[Pp]o ?|[Ll]o ?|[Oo]vl ?|[Vv][Ll]|[Rr]epl|[Rr]eplicator|[Ff]as|[Ss]up-eth|[nN]ve"
   INTERFACE_NUMBER="[0-9]+/[0-9]+\.[0-9]+|[0-9]+/[0-9]+/[0-9]+\.[0-9]+|[0-9]+\.[0-9]+|[0-9]+/[0-9]+/[0-9]+|[0-9]+/[0-9]+|[0-9]+|[0-9]+/[0-9]+/[0-9]+"
#   INTERFACE_NAME="(?:{0})(?:{1})|[Nn]ull".format(INTERFACE_TYPE,INTERFACE_NUMBER)

   INTERFACE_NAME='(?:(?:{0})(?:{1})|(?:[Nn]ull))'.format(INTERFACE_TYPE,INTERFACE_NUMBER)
   INTERFACE_RANGE='(?:(?:{0}-[0-9]+|{0}-{0}|{0}),?)+'.format(INTERFACE_NAME)
   BCM_FP_INTERFACE='([Xx]e([0-9]+))'
   BCM_FP_INTERFACE_RANGE='[Xx]e([0-9]+)-[Xx]e([0-9]+)'

   PHYSICAL_INTERFACE_TYPE="[Ff]ast[Ee]thernet|[Ff][Ee]th|[Gg]igabit[Ee]thernet|[Gg]ig[Ee]|[Gg]i|[Ee]thernet|[Ee]th|Lo"
   PHYSICAL_INTERFACE_NUMBER="[0-9]+/[0-9]+/[0-9]+|[0-9]+/[0-9]+|[0-9]+"
   PHYSICAL_INTERFACE_NAME="(?:{0})(?:{1})".format(PHYSICAL_INTERFACE_TYPE,PHYSICAL_INTERFACE_NUMBER)

   PHYSICAL_INTERFACE_RANGE='(?:(?:{0}-[0-9]+|{0}-{0}|{0}),?)+'.format(PHYSICAL_INTERFACE_NAME)

   DEVICE_TYPE='EOR|sTOR|N9K|N7K|N5K|N3K|N35K|itgen|fanout|UNKNOWN|NA'
   FEX_MODEL='N2148T|N2232P|N2232TM-E|N2248TP-E|N2248T|NB22FJ|NB22HP'
   FEX_INTERFACE_TYPE='(?:{0})[0-9][0-9][0-9]/[0-9]+/[0-9]+'.format(PHYSICAL_INTERFACE_TYPE)
   SWITCH_NAME = '[0-9A-Za-z_-]+(?:\.[A-Za-z]+\.[A-Za-z]+)?'
   #VLAN_RANGE  = '[0-9]+(?:\-[0-9]+)?'

   HEX="[0-9a-fA-F]+"
   HEX_VAL="[x0-9a-fA-F]+"
   MACDELIMITER="[\.:\-]"
   # Following will match the following combinations
   #  Aa.Bb.Cc.Dd.Ee.Ff
   #  Aa-Bb-Cc-Dd-Ee-Ff
   #  Aa:Bb:Cc:Dd:Ee:Ff
   #  AaBb.CcDd.EeFf
   #  AaBb-CcDd-EeFf
   #  AaBb:CcDd:EeFf
   MACADDR=HEX+HEX+MACDELIMITER+HEX+HEX+MACDELIMITER+HEX+HEX+MACDELIMITER+HEX+HEX+MACDELIMITER+HEX+HEX+MACDELIMITER+HEX+HEX+"|"+HEX+HEX+HEX+HEX+MACDELIMITER+HEX+HEX+HEX+HEX+MACDELIMITER+HEX+HEX+HEX+HEX
   IPv4_ADDR="[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
   IPv6_ADDR="[0-9A-Fa-f]+:[0-9A-Fa-f:]+"

   LINK_LOCAL_IPv6_ADDR="fe80::[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+:[0-9A-Fa-f]+"
   IP_ADDRESS="(?:(?:{0})|(?:{1}))".format(IPv4_ADDR,IPv6_ADDR)
   NETADDR ='{0}/[0-9]+'.format(IPv4_ADDR)
   NUM="[0-9]+"
   BOOL="[01]"
   DECIMAL_NUM="[0-9\.]+"
   ALPHA="[a-zA-Z]+"
   ALPHAUPPER="[A-Z]+"
   ALPHALOWER="[a-z]+"
   ALPHASPECIAL="[a-zA-Z_\-\.#/]+"
   ALPHANUM="[a-zA-Z0-9]+"
   ALPHANUMSPECIAL="[a-zA-Z0-9\-\._/]+"
   SYSMGR_SERVICE_NAME = "[a-zA-Z0-9\-\._ ]+"
   VRF_NAME="[a-zA-Z0-9_\-#]+"
   ALL="?:[.\s]+"
   #
   # Number and time formats
   #
   VLAN_RANGE='(?:(?:{0}-[0-9]+|{0}-{0}|{0}),?)+'.format(NUM)

   DATE = '[0-9]+\-[0-9]+\-[0-9]+'
   U_TIME="[0-9]+\.[0-9]+"
   CLOCK_TIME="[0-9]+[0-9]+:[0-9]+[0-9]+:[0-9]+[0-9]+"
   HH_MM_SS="[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}"
   TIME="(?:$U_TIME|$CLOCK_TIME)"
   MONTH="Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
   YEAR="[12]+[0-9][0-9][0-9]"
   UPTIME="(?:\d+[dwmy]\d+[hdwm]|\d+:\d+:\d+|\d+\.\d+)"
   XPTIME="(?:\d+:\d+:\d+|\d+\.\d+|never)"

   LC_STATUS='(?:pwr-?denied|err-?pwd-?dn|pwr-?cycle?d|upgrading|powered-?up|powered-?dn|failure|initializing|testing|ok|present)'
   LC_MODEL='(?:N7K-F2-?48X[PT]-?\d+[E]*| +|Cortina-Test-LC|N9k-X9636PQ|N9K-X9564PX|N9K-X9564TX)'
   FC_MODEL='(?:N7K-C[0-9]+-FAB-?\d+|N/A| +)'
   SC_MODEL='(?:N9K-SC-A)'
   TOR_MODEL='(C93128TX|C9396P)'
   NS_MODEL='(C93128TX|X9564TX|X9564PX|C9396PQ)'
   #LC_MODULE_TYPE='(?:[0-9]+/[0-9]+ Gbps (?:BASE-T )?Ethernet Module|Cortina-Test-LC|Snowbird|Seymour|36p 40G Ethernet Module)' 
   #LC_MODULE_TYPE='(?:[0-9]+/[0-9]+ Gbps (?:BASE-T )?Ethernet Module|Cortina-Test-LC|Snowbird|Seymour|36p 40G Ethernet Module|48x1\/10G \+ 4x40G Ethernet Module|48x1\/10G base\-T 4x40G Ethernet Module)' 
   LC_MODULE_TYPE='(?:[0-9]+/[0-9]+ Gbps (?:BASE-T )?Ethernet Module|Cortina-Test-LC|Snowbird|Seymour|36p 40G Ethernet Module|48x1\/10G SFP\+ 4x40G Ethernet Module|48x1\/10G\-T 4x40G Ethernet Module|Unknown Module)' 
   FC_MODULE_TYPE='(?:Fabric Module(?: [0-9]+)?|Sierra)'
   SC_MODULE_TYPE='(?:System Controller)'
   VLAN_STATUS='active|suspended|act.lshut'
   #Verify_list defined for stimuli classes
   VERIFY_LIST=['none','all','traffic','l2_unicast_pi','l3_unicast_pi','l2_multicast_pi','l3_multicast_pi','l2_unicast_pd','l3_unicast_pd','l2_multicast_pd','l3_multicast_pd','vxlan','system','exception','vpc_consistency','arp_sync','nd_sync']
   TRIGGER_VERIFY_LIST=['traffic','none','all']
   CONFIG_ERROR_LIST='Invalid|Ambiguous|Incomplete|Service not responding'
   CONFIG_ERROR_IGNORE_LIST=''
   EXEC_ERROR_LIST='Invalid|Ambiguous|Incomplete|Service not responding|cannot access file'
   EXEC_ERROR_IGNORE_LIST=''

#========================================================================================#
# execLinuxCommand - Loads debug plugin, by default if debug plugin file name not 
# specified, it uses bootflash:debug_plugin and executes the given Linux command and
# return the output.
#========================================================================================#
class execLinuxCommand(object):

   def  __init__( self, hdl, log, command, debug_plugin='bootflash:debug_plugin' ):

       self.result='pass'
       self.result_message='Executing Linux command on switch succeeded'
       self.log=log
       dp_name = 'dp' + str(random.random())
       cmd='copy {0} volatile:{1}'.format(debug_plugin,dp_name)
       hdl.execute(cmd)
       load_out=hdl.execute('load volatile:{0}'.format(dp_name))
       if re.search( 'Could not load', load_out, flags=re.I ):
           self.log.error('Error loading debug plugin, did not get Linux prompt')
           self.result='fail'
           testResult( 'fail', 'Error loading debug plugin, did not get Linux prompt', self.log,                  \
               skip_flag='test_block' )
           return 
       ex_out=hdl.isendline(command)
       time.sleep(0.5)
       self.log.info(ex_out)
       hdl.isendline('exit')
       time.sleep(0.5)

class installFeatureSet(object):

   def  __init__( self, hdl, log, feature_set ):

       import argparse
       import icon

       self.result='pass'
       self.result_message='Installing Feature-set succeeded'
       self.log=log

       cmd='install feature-set {0}'.format(feature_set)
       hdl.iconfig(cmd)

       time.sleep(5)
       sw_cmd='show feature-set {0}'.format(feature_set)
       show_out=hdl.execute(sw_cmd)
       if re.search( 'uninstalled', show_out, flags=re.I ):
           err_msg='Error in installing feature-set {0}'.format(feature_set)
           self.log.error(err_msg)
           self.result='fail'
           self.result_msg=err_msg
           return

class stopOnFail(Exception):
     def __init__(self,value):
         self.value = value
     def __str__(self):
         return self.value

def PauseOnFail(log,log_dir,email_proc,failed_case):
    username=getpass.getuser()
    time_now=int(time.time())
    pause_filename=os.path.join(log_dir,'testfailed-{0}-{1}.pauseOnFail'\
        .format(username,time_now))
    stop_filename=os.path.join(log_dir,'testfailed-{0}-{1}.stoptest'\
        .format(username,time_now))
    disable_pause_filename=os.path.join(log_dir,'testfailed-{0}-{1}.disablePause'\
        .format(username,time_now))
    os.system('touch {0}'.format(pause_filename))
    msg='''\nTests have been paused due to a failure 
    1. To continue(unpause)   :    rm {0}
    2. To stop(graceful)      :    touch {1}
    3. To abort(ungraceful)   :    type ctrl-c
    4. To disable pauseonfail :    touch {2}\n'''.format(pause_filename,stop_filename,disable_pause_filename)
    log.info(msg)
    log.handlers[0].flush()
    email_proc(failed_case,msg)
    print (msg)
    sys.stdout.flush()
    while os.path.isfile(pause_filename):
        time.sleep(5)
        if os.path.isfile(stop_filename):
            raise stopOnFail('User stopped tests after running into pauseOnFail') 
            return 1
        if os.path.isfile(disable_pause_filename):
            # set hlite.gd['parseoutput'].pauseonfail to False
            return 2
    return 0


# Define this function only if not running in harness mode
if 'harness' not in sys.modules.keys():
    def testResult(result, msg, log, skip_flag=None):
        '''Logs appropriate message and raise exception(if specified).'''

        currentlevel=1
        notupdated=True
        while notupdated and currentlevel < 10:
           if len(inspect.stack()) > currentlevel:
               testcaseargs=inspect.getargvalues(inspect.stack()[currentlevel][0])
               if len(testcaseargs) > 3:
                   if 'self' in testcaseargs[3]:
                       if 'reportlogs' in dir(testcaseargs[3]['self']):
                           testcaseargs[3]['self'].reportlogs.append(msg)
                           notupdated=False
                       if 'hlite' in dir(testcaseargs[3]['self']):
                           if testcaseargs[3]['self'].hlite.gd['parseoutput'].stoponfail and (result=='fail' or result =='abort'):
                               raise stopOnFail("Stop on Fail {0}".format(msg))
                           if testcaseargs[3]['self'].hlite.gd['parseoutput'].pauseonfail and result=='fail':
                               log.error('FAILED:{0}'.format(msg))
                               email_proc=testcaseargs[3]['self'].hlite.emailpauseonfail
                               failed_case=testcaseargs[3]['self'].__class__
                               log_dir=os.path.dirname(testcaseargs[3]['self'].hlite.gd['parseoutput'].logfile)
                               if not log_dir:
                                   log_dir=os.getcwd()
                               ret_val=PauseOnFail(log,log_dir,email_proc,failed_case)
                               if ret_val==2:
                                   # set hlite.gd['parseoutput'].pauseonfail to False
                                   testcaseargs[3]['self'].hlite.gd['parseoutput'].pauseonfail=False
                           if result=='abort':
                               raise Exception(msg)
                           if result=='fail':
                               testcaseargs[3]['self'].result='fail'
                           notupdated=False
           currentlevel=currentlevel+1
        

        if re.search( 'fail', result, flags=re.I ):
            log.error('FAILED:{0}'.format(msg))
            callerargs=inspect.getargvalues(inspect.stack()[1][0])
            if len(callerargs) > 3:
                if 'self' in callerargs[3]:
                   if 'result' in dir(callerargs[3]['self']):
                       callerargs[3]['self'].result=result
        if re.search( 'pass', result, flags=re.I ):
            log.info('PASSED:{0}'.format(msg))
        if skip_flag != None and re.search( 'test_block', skip_flag, flags=re.I ):
            log.error('Skipping the rest of the test block')
            raise Exception('SkipTestBlock From eor_utils')
        elif skip_flag != None and re.search( 'test_case', skip_flag, flags=re.I ):
            log.error('Skipping the rest of the test case')
            raise Exception('SkipTestCase_From eor_utils')
        else:
            return

# Post demo, this needs to be changed to get the patterns from harness.gd

#try:
#   path=os.path.dirname(os.path.abspath(__file__))
#   fp=open('{0}/syslogchecks.yml'.format(path),"r")
#   ds=yaml.load(fp)
#   fp.close()
#   syslogcheckdict=ds['syslog_errors_dict']
#except:
#   print ("Error opening syslogchecks.yml")


def getBfdGlobalInterval (hdl,log):
    print('Fetch the Bfd Interval Global Configuration')
    log.info('Fetch the Bfd Interval Global Configuration')
    show_run_bfd = hdl.execute('show running bfd')
    show_run_bfd = show_run_bfd.split('\n')
    bfdPat='bfd interval ([0-9]+) min_rx ([0-9]+) multiplier ([0-9]+)'
    intfPat='interface .*'
    for line in show_run_bfd:
      bfdIntv=re.findall( bfdPat, line )
      intfConf=re.findall( intfPat, line )
      if bfdIntv == []:
        if intfConf == []:
          continue
        else:
          log.info ('No Bfd Global Timers configured on switch {0}'.format(hdl.switchName))
          return 0
      else:
        log.info ('Bfd Global Timers configured on switch {0}'.format(hdl.switchName))
        return bfdIntv[0]


def getBfdInterfaceInterval (hdl,interface,log):
    print('Fetch the Bfd Interval Config for Interface')
    log.info('Fetch the Bfd Interval Config for Interface')
    show_int=hdl.execute('show running interface {0}'.format(interface))
    pat='bfd interval ([0-9]+) min_rx ([0-9]+) multiplier ([0-9]+)'
    bfdIntv=re.findall( pat, show_int)
    print('Temp: {0}'.format(bfdIntv))
    if bfdIntv == []:
        log.info ('No Bfd Timers configured for intf {0} on switch {1}'.format(interface,hdl.switchName))
        return 0
    else:
        return bfdIntv[0]

def loginToServer(log, *args):
    arggrammar = {}
    arggrammar['server'] = '-type str -required True -format {0}|{1}'.format(rex.IPv4_ADDR,rex.IPv6_ADDR)
    arggrammar['user'] = '-type str -default root'
    arggrammar['password'] = '-type str -default nbv12345'
    ns = parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    cmd = 'ssh {0}@{1}'.format(ns.user,ns.server)
    server_hdl = pexpect.spawn(cmd,timeout=50)
    server_hdl.send("\r")
    server_hdl.expect('[pP]assword:')
    server_hdl.send("{0}\r".format(ns.password))
    server_hdl.expect('# $')
    return server_hdl




def getSflowAgentIp(srv_hdl,log):
    log.info('Getting the process ID for SFLOWTOOL')
    srv_hdl.sendline("ps -eaf | grep sflowtool")
    srv_hdl.expect('\[.*#')
    ls_var = ''
    ls_var = srv_hdl.before
    log.info('Process command executed on server is {0}'.format(ls_var))
    pat = '[A-Za-z]+[ \t]+([0-9]+)[ \t 0-9 : \/ A-Z a-z ?]+[ \t]+[0-9 : \t]+sflowtool'
    out2 = re.findall(pat, ls_var)
    print (out2)
    log.info('Regular expression matches or not {0}'.format(out2))
    if not out2:
        log.info('SFLOWTOOL IS NOT ENABLED, SO ENABLE IT ')
    else:
        log.info('SFLOWTOOL is already enabled ,so kill it and enable it newly')
        print (int(out2[0]))
        srv_hdl.sendline("kill -9 {0}".format(int(out2[0])))
        srv_hdl.expect('\[.*#')
        log.info('Got the prompt \n')
    srv_hdl.sendline("sflowtool > ~/sflow.log & ")
    srv_hdl.expect('\[.*#')
    log.info('Got the prompt \n')
    print('Got the Prompt \n ')
    srv_hdl.sendline("ps -eaf | grep sflowtool")
    srv_hdl.expect('\[.*#')
    ls_var1 = srv_hdl.before
    log.info('Process command executed on server is {0}'.format(ls_var1))
    pat = '[A-Za-z]+[ \t]+([0-9]+)[ \t 0-9 : \/ A-Z a-z ?]+[ \t]+[0-9 : \t]+sflowtool'
    out1 = re.findall(pat, ls_var1)
    print ('output of command {0} ',format(out1))
    if not out1:
        testResult('fail', 'Failed to execute sflowtool command on server',log)
        return
    else:
        testResult('pass', 'Successfully executed command on the server',log)

    srv_hdl.sendline("cat ~/sflow.log | grep agent 91.2.1.10")
    srv_hdl.expect('\[.*#')
    ls_var1 = srv_hdl.before
    log.info('Process command executed on server is {0}'.format(ls_var1))
    return

def getPortChannelList( hdl, log ):

    import icon
    import re
    print('Fetch the list of port-channels')
    log.info('Fetch the list of port-channels configured')
    show_pc=hdl.execute('show port-channel summary')
    pat='\s+(Po[0-9]+)'
    pc_list=re.findall( pat, show_pc )
    if len(pc_list)==0:
         print('No port-channels configured on this box, list empty')
    return pc_list 


def getPortChannelMemberList( hdl,log,*args):
    # Returns list of members of the given port-channel number using mandatory argument pc_nam
    # Can be used to return only the member ports that are up using optional argument state
    # Can be used to return only the member ports that are down using optional argument state
    # Can be used to return the the control link member 

    import icon
    import re
    arggrammar={}
    arggrammar['pc_nam']='-type str -required True'
    arggrammar['state']='-type str'
    arggrammar['control']='-type bool'

    argOptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # remove 'po' from pc_nam since rest of the proc is expecting pc_nam to be a number only
    argOptions.pc_nam=re.sub('[pP]o','',str(argOptions.pc_nam))

    msg='Fetch list of Port Channel Members in ' + str(argOptions.pc_nam)
    log.info(msg)
    command = "show port-channel database interface Po"
    sw_cmd = command + str(argOptions.pc_nam)
    show_int_pc=hdl.execute(sw_cmd)

    if argOptions.control:
         ctrl_pat=".*\*"
    else:
         ctrl_pat=".*"
    if argOptions.pc_nam:
         pat="("+rex.INTERFACE_NAME+").*\[" + ctrl_pat
         pc_memb_list=re.findall(pat, show_int_pc, flags=re.I )
         msg='Members in port-channel ' + str(argOptions.pc_nam) + str(pc_memb_list)
         log.info(msg)

    if argOptions.state=='up':
         pat="("+rex.INTERFACE_NAME+").*\[.*up" + ctrl_pat
         pc_memb_list=re.findall(pat, show_int_pc, flags=re.I )
         msg='Members that are up in port-channel ' + str(argOptions.pc_nam) + str(pc_memb_list)
         log.info(msg)

    if argOptions.state=='down':
         pat="("+rex.INTERFACE_NAME+").*\[.*down" + ctrl_pat
         pc_memb_list=re.findall(pat, show_int_pc, flags=re.I )
         msg='Members that are down in port-channel ' + str(argOptions.pc_nam) + str(pc_memb_list)
         log.info(msg)

    if len(pc_memb_list)==0:
         msg='No Members found in this port-channel ' + str(argOptions.pc_nam)
         log.info(msg)
    if not pc_memb_list:
         msg='PC member list is null'
    return pc_memb_list




def getPortChannelDict( hdl,log,*args):

    """
    Returns the port-channel database in dictionary format, accepts state as a filter option
    and returns the port-channel database just for the PCs in that state.
    Usage: 
    getPortChannelDict( hdl, log )
    getPortChannelDict( hdl, log, '-state up' )
    """

    import icon
    import re
    arggrammar={}
    arggrammar['state']='-type str -choices ["up","down"]'
    arggrammar['skip_list']='-type str -choices ["fex-fabric"]'

    argOptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # Get the list of port-channels
    pc_list=getPortChannelList( hdl, log )
    log.debug('List of Port-channels = ' + str(pc_list))

    pc_dict={}

    for pc_nam in pc_list: 
        command = "show port-channel database interface "
        sw_cmd = command + str(pc_nam)
        show_int_pc=hdl.execute(sw_cmd)
        if argOptions.state:
           if re.search( 'up', argOptions.state, re.I ):
              pat="("+rex.INTERFACE_NAME+").*\[.*up"
           elif re.search( 'down', argOptions.state, re.I ):
              pat="("+rex.INTERFACE_NAME+").*\[.*down"
        else:
           pat="("+rex.INTERFACE_NAME+").*\["
        pc_memb_list=re.findall(pat, show_int_pc, flags=re.I )
        if argOptions.skip_list:
           if re.search( 'fex-fabric', argOptions.skip_list, re.I ):
              sw_cmd='show interface {0}'.format(pc_nam)
              show_int=hdl.execute(sw_cmd)
              if not re.search( 'fex-fabric', show_int, re.I ):
                 pc_dict[pc_nam]=pc_memb_list
        else:
           pc_dict[pc_nam]=pc_memb_list

    return pc_dict
        




def getFexModuleList(hdl, log, *args):
    '''Returns list of Online FEX IDs by default.

    Usage:
     fex_list=getFexModuleList(hdl,log)
     fex_list=getFexModuleList(hdl,log,'-model N2K-C2232') # FEX IDs of a particular model
     fex_list=getFexModuleList(hdl,log,'-state offline') # FEX IDs in particular state
     fex_list=getFexModuleList(hdl,log,'-fabrics eth1/1,eth1/2') # FEX IDs with one/more of these fabric ports

    When "-fabrics" is used, "-model" and "-state" cannot be used'''

    arggrammar={}
    arggrammar['model']='-type str'
    arggrammar['state']='-type str' # Use 'any' to get a list of all FEXs in output of 'show fex'
    arggrammar['fabrics']='-type str -format {0}'.format(rex.PHYSICAL_INTERFACE_RANGE)
    arggrammar['mutualExclusive'] =[('fabrics','model'),('fabrics','state')]

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return []

    command='show fex'
    model='.*'
    state='Online(?! Sequence)'
    fex_list=[]

    if options_namespace.model:
        model=options_namespace.model
    if options_namespace.state:
        state=options_namespace.state
        if state.lower()=='online':
            state='Online(?! Sequence)'
        if state.lower()=='any':
            state='.*'

    if options_namespace.fabrics:
        fabrics_list=strtoexpandedlist(options_namespace.fabrics)
        show_output=hdl.execute('show interface fex-fabric')
        for port in fabrics_list:
            port=normalizeInterfaceName(log,port)
            result=re.search('([0-9]+)[ \t]+{0}[ \t]+'.format(port),show_output)
            if result:
                fex_list.append(result.group(1))
            else:
                log.error('No FEX associated with port {0}'.format(port))
                return []
        fex_list=list(set(fex_list))
    else:
        show_output=hdl.execute(command)
        fex_list=re.findall('^([0-9]+)[ \t]+[^ \t]+[ \t]+{0}[ \t]+{1}'.format(state,model),\
            show_output,re.M | re.I)

    return fex_list

def getRunningConfig(hdl, log, *args):
    '''Returns output of 'show running-config

    Usage:
     run_output=getRunningConfig(hdl,log) 
     run_output=getRunningConfig(hdl,log,'-interface eth1/1') # Return config for that interface 
     run_output=getRunningConfig(hdl,log,'-component aaa') # Return config for that component 
     run_output=getRunningConfig(hdl,log,'-grep radius') # Return whatever the grep returns
     run_output=getRunningConfig(hdl,log,'-nocomments') # Remove comments from output and return
     run_output=getRunningConfig(hdl,log,'-noversion') # Remove version string from output'''

    arggrammar={}
    arggrammar['component']='-type str'
    arggrammar['interface']='-type str -format {0}'.format(rex.INTERFACE_NAME)
    arggrammar['grep']='-type str'
    arggrammar['nocomments']='-type bool -default True'
    arggrammar['noversion']='-type bool -default True'
    arggrammar['fex_hif']='-type str -format [0-9,]+'
    arggrammar['fex_global']='-type str -format [0-9, ]+'
    arggrammar['fex_fabric']='-type str -format [0-9, ]+'
    arggrammar['mutualExclusive'] =[('fex_hif','fex_global','fex_fabric','component','interface'),\
                                    ('fex_hif','fex_global','fex_fabric','grep')]

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return ''

    command='show running-config'

    if options_namespace.component:
        command=command + ' ' + options_namespace.component
    if options_namespace.interface:
        command=command + ' interface ' + options_namespace.interface
    if options_namespace.grep:
        command=command + ' | grep ' + options_namespace.grep
    if options_namespace.nocomments:
        command=command + ' | grep -v \"^!\"'
    if options_namespace.noversion:
        command=command + ' | grep -v \"^version"'

    show_output=hdl.execute(command)
    if re.search('Invalid command at \'\^\' marker',show_output,re.I):
        log.warning('Invalid command:' + show_output)

    if options_namespace.fex_hif:
        return_output=''
        fex_list=re.split('[ ,]+',options_namespace.fex_hif)
        for fex_id in fex_list:
            hif_config=''.join(re.findall('^interface Ethernet{0}(?![0-9]).*?\n(?=[^ \t])'.format(fex_id),\
                show_output,re.I|re.M|re.DOTALL))
            return_output+=hif_config
        show_output=return_output
    if options_namespace.fex_global:
        return_output=''
        fex_list=re.split('[ ,]+',options_namespace.fex_global)
        for fex_id in fex_list:
            fex_global=''.join(re.findall('^fex {0}.*?\n(?=[^ \t])'.format(fex_id),\
                show_output,re.I|re.M|re.DOTALL))
            return_output+=fex_global
        show_output=return_output
    if options_namespace.fex_fabric:
        return_output=''
        fex_list=re.split('[ ,]+',options_namespace.fex_fabric)
        fex_details_dict=getFexdetailDict(hdl,log,'-fex {0}'.format(fex_list))
        for fex_id in fex_list:
            if 'Fabric_interface' in fex_details_dict[fex_id]:
                for fabric_intf in fex_details_dict[fex_id]['Fabric_interface']:
                    intf_number=re.search('({0})'.format(rex.INTERFACE_NUMBER),fabric_intf).group(1)
                    if re.search('^Po',fabric_intf):
                        intf='port-channel' + intf_number
                    elif re.search('^[Ee]th',fabric_intf):
                        intf='Ethernet' + intf_number
                    intf_config=''.join(re.findall('^interface {0}(?![0-9]).*?\n(?=[^ \t])'.format(intf),\
                        show_output,re.I|re.M|re.DOTALL))
                    return_output+=intf_config
        show_output=return_output

    return show_output


def getStartupConfig(hdl, log, *args):
    '''Returns output of 'show startup-config'.

    Usage:
     start_output=getStartupConfig(hdl,log) 
     start_output=getStartupConfig(hdl,log,'-interface eth1/1') # Return config for that interface 
     start_output=getStartupConfig(hdl,log,'-component aaa') # Return config for that component 
     start_output=getStartupConfig(hdl,log,'-grep radius') # Return whatever the grep returns
     start_output=getStartupConfig(hdl,log,'-nocomments') # Remove comments from output and return
     start_output=getStartupConfig(hdl,log,'-noversion') # Remove version string from output'''

    arggrammar={}
    arggrammar['component']='-type str'
    arggrammar['interface']='-type str'
    arggrammar['grep']='-type str'
    arggrammar['nocomments']='-type bool -default True'
    arggrammar['noversion']='-type bool -default True'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return ''

    command='show startup-config'

    if options_namespace.component:
        command=command + ' ' + options_namespace.component
    if options_namespace.interface:
        command=command + ' interface ' + options_namespace.interface
    if options_namespace.grep:
        command=command + ' | grep ' + options_namespace.grep
    if options_namespace.nocomments:
        command=command + ' | grep -v \"^!\"'
    if options_namespace.noversion:
        command=command + ' | grep -v \"^version"'

    show_output=hdl.execute(command)
    if re.search('Invalid command at \'\^\' marker',show_output,re.I):
        log.warning('Invalid command:' + show_output)

    return show_output


def getVrfDict(hdl, log, *args):

    # Returns VRF dictionary with name as key first level key and id, state, \
    #     reason as second level keys. If passed with vrfname as an arg \
    #     then id, state, reason will be first level keys

    arggrammar={}
    arggrammar['vrf_name'] = ''
    
    optionsNamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    command="show vrf "
    if optionsNamespace.vrf_name:
       command = command +  optionsNamespace.vrf_name

    showOutput=hdl.execute(command)

    vrf_list=re.findall(\
     "^({0})[ \t]*([0-9]+)[ \t]*([a-zA-Z]+)[ \t]*([a-zA-Z0-9_\-]+)".format(rex.VRF_NAME),\
     showOutput, re.M | re.I)

    if optionsNamespace.vrf_name:
        returnDict=convertListToDict(vrf_list,['VRF-Name','VRF-ID','State','Reason']) 
    else:
        returnDict=convertListToDict(vrf_list,['VRF-Name','VRF-ID','State','Reason'],'VRF-Name') 

    log.debug("VRF Dictionary " + str(returnDict))
    return returnDict

def convertListToDict(table,columns=[],keys=None,keytype="tuple"):

    # Returns dictionary based on given list & columns
    # If it is a list, each column is a key
    # If it is a list of lists, then first level keys are passed keys argument
    # and columns is second level key

    returnDict = collections.OrderedDict()
    if keys: 
        keyIndexes = []
        if "split" in dir(keys):
            keys=keys.split()
        for key in keys:
            keyIndexes.append(columns.index(key))

        valueIndex=-1
        if len(columns) - len(keys) == 1:
            for i in range(len(columns)):
                if not i in keyIndexes:
                   valueIndex=i
                   break

        for row in table:
            key=""
            keyitems=[]
            initial=True
            for keyIndex in keyIndexes:
               interface=""
               temp=re.match(rex.INTERFACE_NAME,row[keyIndex])
               if temp and temp.group(0) == row[keyIndex]:
                   interface=normalizeInterfaceName("",row[keyIndex]) 
               if initial:
                   if interface == "": 
                       key = key + row[keyIndex]
                   else:
                       key = key + interface
                   initial=False
               else:
                   if interface == "": 
                       key = key + " " + row[keyIndex]
                   else:
                       key = key + " " + interface
               if interface == "":
                   keyitems.append(row[keyIndex])
               else:
                   keyitems.append(interface)
            if keytype == "tuple" and len(keys) > 1:
                key=tuple(keyitems)
            returnDict[key] = collections.OrderedDict()
            if valueIndex == -1:
                for i in range(len(columns)):
                    if not i in keyIndexes:
                       temp=re.match(rex.INTERFACE_NAME,row[i].strip())
                       if temp and temp.group(0) == row[i].strip():
                          returnDict[key][columns[i]]=normalizeInterfaceName("",row[i].strip()) 
                       else:
                           returnDict[key][columns[i]] = row[i].strip()
            else:
               temp=re.match(rex.INTERFACE_NAME,row[valueIndex].strip())
               if temp and temp.group(0) == row[valueIndex].strip():
                   returnDict[key]=normalizeInterfaceName("",row[valueIndex].strip()) 
               else:
                   returnDict[key] = row[valueIndex]
    else:
        #Single level dictionary need to handle 6 different use cases
        #eor_utils.convertListToDict(['x','y','z'],['a','b','c'])
        #eor_utils.convertListToDict([],['a','b','c'])
        #eor_utils.convertListToDict(['x','y'],['a','b','c'])
        #eor_utils.convertListToDict([('x','y','z')],['a','b','c'])
        #eor_utils.convertListToDict([('x','y'),('c','d')],['a','b'])
        #eor_utils.convertListToDict([('x','y'),('c','d')])
        if len(table):
            if len(columns) == len(table) and not re.search('tuple',str(type(table[0]))):
                for key in columns:
                    temp=re.match(rex.INTERFACE_NAME,table[columns.index(key)])
                    if temp and temp.group(0) == table[columns.index(key)]:
                        returnDict[key]=normalizeInterfaceName("",table[columns.index(key)]) 
                    else:
                        returnDict[key]=table[columns.index(key)]
            elif len(table) == 1 and len(table[0]) == len(columns) and re.search('tuple',str(type(table[0]))):
                for key in columns:
                    temp=re.match(rex.INTERFACE_NAME,table[0][columns.index(key)])
                    if temp and temp.group(0) == table[0][columns.index(key)]:
                        returnDict[key]=normalizeInterfaceName("",table[0][columns.index(key)]) 
                    else:
                        returnDict[key]=table[0][columns.index(key)]
            elif (len(columns) == 2 or len(columns) == 0)and re.search('tuple',str(type(table[0]))):
                for row in table:
                    if len(row) == 2:
                       temp=re.match(rex.INTERFACE_NAME,row[1])
                       if temp and temp.group(0) == row[1]:
                            returnDict[row[0]]=normalizeInterfaceName("",row[1]) 
                       else:
                            returnDict[row[0]]=row[1]
                    else:
                       return collections.OrderedDict()
    return returnDict

def getVrfList(hdl,log):

    # Returns Vrf list
    vrfdict=getVrfDict(hdl,log)
    keys=vrfdict.keys()
    log.debug("VRF List " + str(keys))
    return keys


def getBfdNeighborDict( hdl, log, *args ):

    """
    Parses the output of show bfd neighbors with appropriate options and returns in dictionary format
    # OurAddr     NeighAddr       LD/RD             RH/RS   Holdown(mult)    State    Int          Vrf  
    # 30.10.10.1 30.10.10.3   1090519042/1124073474 Up      78427(40)        Up     Eth4/11      default  
    """

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbor']='-type str'
    arggrammar['application']='-type str -choices ["bgp","eigrp","ospf"]'
    arggrammar['interface']='-type str'
    arggrammar['src_ip']='-type str'
    arggrammar['dst_ip']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    # This output is for debug purpose
    debug_cmd = 'show bfd neighbors | grep Up | count'
    show_out=hdl.execute(debug_cmd)

    cmd='show bfd neighbors '

    if hasattr( ns, 'vrf' ) and ns.vrf is not None:
        cmd = cmd + 'vrf {0}'.format(ns.vrf)

    if hasattr( ns, 'application' ) and ns.application is not None:
        cmd = cmd + 'application {0}'.format(ns.application)

    if hasattr( ns, 'neighbor' ) and ns.neighbor is not None:
        cmd = cmd + 'neighbor {0}'.format(ns.neighbor)

    if hasattr( ns, 'interface' ) and ns.interface is not None:
        cmd = cmd + 'interface {0}'.format(ns.interface)

    if hasattr( ns, 'src_ip' ) and ns.src_ip is not None:
        cmd = cmd + 'src-ip {0}'.format(ns.src_ip)

    if hasattr( ns, 'dst_ip' ) and ns.dst_ip is not None:
        cmd = cmd + 'dst-ip {0}'.format(ns.dst_ip)
    show_out=hdl.execute(cmd)
    neigh_list=re.findall(\
      '({0})\s+({1})\s+({2})/({3})\s+({4})\s+({5})\(({6})\)\s+({7})\s+({8})\s+({9})'.format( \
      rex.IPv4_ADDR, rex.IPv4_ADDR, rex.NUM, rex.NUM, rex.ALPHA, '[0-9N\/A]+', rex.NUM, rex.ALPHA, \
      rex.INTERFACE_NAME, rex.VRF_NAME ), show_out )
    bfd_dict={}
    bfd_dict=convertListToDict( neigh_list, ['OurAddr', 'NeighAddr', 'LD', 'RD', 'RH/RS',     \
       'Holdown', 'mult', 'State', 'Int', 'Vrf' ], ['NeighAddr','Int'])

    return bfd_dict




#==================================================================================#
# getIpv4InterfaceBriefDict - Method to return the output of 'show ip interface brief'
# in a dictionary format with Interface being the key ..
#
# Mandatory Args
# hdl - icon switch object
# log - harness/python logger object
#
# Optional Args
# vrf - VRF name - default is 'default'
# status - Interface status, choices - up, down, all. default is all.
#
# Usage
# getIpv4InterfaceBriefDict(hdl, log)
# getIpv4InterfaceBriefDict(hdl, log, '-vrf <vrf_name> -status up')
#==================================================================================#

def getIpv4InterfaceBriefDict( hdl, log, *args ):

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['status']='-type str -choices ["up","down","all"] -default all'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if re.search( 'up', ns.status, re.I ):
        if ns.vrf:
            cmd='show ip interface brief vrf {0} | inc protocol-up/link-up'.format(ns.vrf)
        else:
            cmd='show ip interface brief vrf default | inc protocol-up/link-up'
    elif re.search( 'down', ns.status, re.I ):
        if ns.vrf:
            cmd='show ip interface brief vrf {0} | inc protocol-down'.format(ns.vrf)
        else:
            cmd='show ip interface brief vrf default | inc protocol-down'
    else:
        if ns.vrf:
            cmd='show ip interface brief vrf {0}'.format(ns.vrf)
        else:
            cmd='show ip interface brief vrf default'


    show_out=hdl.execute(cmd)
    intf_list=re.findall(\
       '({0})\s+({1})\s+([a-zA-Z\-\/]+)'.format(rex.INTERFACE_NAME, rex.IPv4_ADDR), show_out )
    ipv4_dict={}
    ipv4_dict=convertListToDict( intf_list, ['Interface', 'IP Address', 'Interface Status'], 'Interface' )
    #log.debug('ipv4_dict = {0}'.format(ipv4_dict))
    return ipv4_dict


def getIpv4Addresses(hdl, log, *args ):
    '''
    anandksi(03/27/2014)
    get all IP addresses on the box for verifying connectivity
    takes care of VRF as well - except HSRP/VRRP which works only for default vrf
    '''

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['status']='-type str -choices ["up","down","all"] -default all'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if ns.vrf:
        args = '-vrf {0} -status {1}'.format(ns.vrf,ns.status)
    else:
        args = '-status {0}'.format(ns.status)
    ipv4_dict = getIpv4InterfaceBriefDict(hdl,log,args)
    ip_addr_list = []
    for intf in ipv4_dict.keys():
        ip_addr_list.append(ipv4_dict[intf]['IP Address'])
    #FHRP addresses are taken care only for default vrf
    if ns.vrf:
        # get all HSRP/VRRP IP
        hsrp_dict = getHsrpDict(hdl,log)
        for intf in hsrp_dict.keys():
            ip_addr_list.append(hsrp_dict[intf]['Virtual IP address'])
        vrrp_dict = getVrrpv2Dict(hdl,log)
        for intf in vrrp_dict.keys():
            ip_addr_list.append(vrrp_dict[intf]['Virtual_IP_address'])
    return ip_addr_list



#==================================================================================#
# getIpv6InterfaceBriefDict - Method to return the output of 'show ipv6 interface brief'
# in a dictionary format with Interface being the key ..
#
# Mandatory Args
# hdl - icon switch object
# log - harness/python logger object
#
#
# Optional Args
# vrf - VRF name - default is 'default'
# status - Interface status, choices - up, down, all. default is all.
#
# Usage
# getIpv6InterfaceBriefDict(hdl, log)
# getIpv6InterfaceBriefDict(hdl, log, '-vrf <vrf_name> -status up')
#==================================================================================#

def getIpv6InterfaceBriefDict( hdl, log, *args ):

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['status']='-type str -choices ["up","down","all"] -default all'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)


    if re.search( 'up', ns.status, re.I ):
        if ns.vrf:
            cmd='show ipv6 interface brief vrf {0} | grep -A 2 up'.format(ns.vrf)
        else:
            cmd='show ipv6 interface brief vrf default | grep -A 2 up'
    elif re.search( 'down', ns.status, re.I ):
        if ns.vrf:
            cmd='show ipv6 interface brief vrf {0} | grep -A 2 down'.format(ns.vrf)
        else:
            cmd='show ipv6 interface brief vrf default | grep -A 2 down'
    else:
        if ns.vrf:
            cmd='show ipv6 interface brief vrf {0}'.format(ns.vrf)
        else:
            cmd='show ipv6 interface brief vrf default'


    show_out=hdl.execute(cmd)
    intf_list=re.findall(\
       '({0})\s+({1})\s+([a-zA-Z\-\/]+)\s+({1})'.format(rex.INTERFACE_NAME, rex.IPv6_ADDR), show_out )
  
    ipv6_dict={} 
    ipv6_dict=convertListToDict( intf_list, ['Interface', 'IPv6 Address', 'Interface Status',  \
         'Link-local Address'], 'Interface' )
    return ipv6_dict



def getIpv6Addresses(hdl, log, *args ):
    '''
    anandksi(03/27/2014)
    get all IPv6 addresses on the box for verifying connectivity
    takes care of VRF as well - except HSRP/VRRP which needs to be added
    '''

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['status']='-type str -choices ["up","down","all"] -default all'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if ns.vrf:
        args = '-vrf {0} -status {1}'.format(ns.vrf,ns.status)
    else:
        args = '-status {0}'.format(ns.status)
    ipv6_dict = getIpv6InterfaceBriefDict(hdl,log,args)
    ipv6_addr_list = []
    for intf in ipv6_dict.keys():
        ipv6_addr_list.append(ipv6_dict[intf]['IPv6 Address'])
    #HSRP addresses need to be added
    if ns.vrf:
        # get all HSRP/VRRP IP
        pass
    return ipv6_addr_list



def getInterfaceBriefDict(hdl, log, *args):
    # Returns Interface dictionary with interface name as first level key
    #  and VLAN, Type, Mode, Status, Reason,Speed,PCNum as second level keys

    arggrammar={}
    arggrammar['interface']='-type str -format {0}'.format(rex.INTERFACE_RANGE)

    options=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options.VALIDARGS:
        log.warning('Invalid arguments')
        return {}

    if options.interface:
        command="show interface {0} brief".format(options.interface)
        search=re.search('(?:int|int[erface]+) ((?:{0}| +)+)'.format(rex.INTERFACE_RANGE),command,re.I)
        if search and re.search(',',search.group(1)):
            # Split non-homogeneous ranges and get cumulative output
            intf_list=re.split('[, ]+',search.group(1))
            intf_list=filter(None, intf_list)
            intf_dict={}
            intf_dict['fex_intf']=[intf for intf in intf_list \
                if re.search('eth[ernet]*[0-9]+/[0-9]+/[0-9]+',intf,re.I)]
            intf_dict['switch_intf']=[intf for intf in intf_list \
                if re.search('eth[ernet]*[0-9]+/[0-9]+(?!(/[0-9]+|\.[0-9]+))',intf,re.I)]
            intf_dict['switch_sub_intf']=[intf for intf in intf_list \
                if re.search('eth[ernet]*[0-9]+/[0-9]+\.[0-9]+',intf,re.I)]
            intf_dict['po_intf']=[intf for intf in intf_list \
                if re.search('po[rtchannel-]*[0-9]+',intf,re.I)]
            intf_dict['svi_intf']=[intf for intf in intf_list \
                if re.search('vlan[0-9]+',intf,re.I)]
            intf_dict['lo_intf']=[intf for intf in intf_list \
                if re.search('lo[opback]*[0-9]+',intf,re.I)]
            if len(intf_list) != len(intf_dict['switch_intf'])+len(intf_dict['switch_sub_intf'])+len(intf_dict['fex_intf'])+\
                len(intf_dict['po_intf'])+len(intf_dict['svi_intf'])+len(intf_dict['lo_intf']):
                testResult('fail','Could not identify one of the interface types',log)
                return ''
            showoutput=''
            for intf_type in intf_dict:
                if intf_dict[intf_type]:
                    intf_range=','.join(intf_dict[intf_type])
                    new_cmd=re.sub('(?:int|int[erface]+) (?:{0}| +)+'.format(rex.INTERFACE_RANGE),'int {0} '.format(intf_range),command,re.I)
                    showoutput+=hdl.execute(new_cmd)
        else:
            showoutput=hdl.execute(command)
    else:
        command="show interface brief"
        showoutput=hdl.execute(command)

    interface_list=re.findall(\
     "("+rex.INTERFACE_NAME+")[ \t]+([0-9\-]+)[ \t]*([A-Za-z]+)[ \t]*([a-zA-Z]+)[ \t]*([a-zA-Z]+)[ \t]*([a-zA-Z ]+)[ \t]+([0-9A-Za-z]+)[ \(\)A-Z\t]*([0-9\-A-Z-a-z]+)",\
     showoutput)

    mgmt_interface_list=re.findall("(Mgmt[0-9/]+)[ \t]+([a-zA-Z0-9_\-]+)[ \t]+([a-zA-Z]+)[ \t]+([0-9\.]+)[ \t]+([0-9G]+)[ \t]+([0-9]+)", showoutput, re.M | re.I)
    loopback_interface_list=re.findall("(lo[opback]*[0-9]+)[ \t]+([a-zA-Z]+)[ \t]+([^\r\n]+)[\r\n]+", showoutput,re.I)
    po_interface_list=re.findall("(po[rtchannel-]*[0-9]+)[ \t]+([0-9\-]+)[ \t]+(\S+)[ \t]+(\S+)[ \t]+(\S+)[ \t]+([a-zA-Z ]+)[ \t]+(\S+)[ \t]+(\S+)",showoutput,re.I)
    svi_interface_list=re.findall("(Vlan[0-9/]+)[ \t]+([a-zA-Z\-]+)[ \t]+([a-zA-Z]+)[ \t]+([^\r\n]+[\r\n]+)", showoutput)
    nve_interface_list=re.findall("(nve[0-9]+)[ \t]+([a-zA-Z]+)[ \t]+([a-zA-Z]+)", showoutput)
    tunnel_interface_list=re.findall("(Tunnel[0-9/]+)[ \t]+([a-zA-Z]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([0-9]+)", showoutput, re.M | re.I)
    monitor_list=re.findall(\
     "("+rex.INTERFACE_NAME+")[ \t]+(monitor)[ \t]*([A-Za-z]+)[ \t]*([a-zA-Z]+)[ \t]*([a-zA-Z]+)[ \t]*([a-zA-Z ]+)[ \t]+([0-9A-Za-z]+)[ \(\)A-Z\t]*([0-9\-A-Z-a-z]+)",\
     showoutput)

    #intDict=convertListToDict(interface_list,['Interface','Vlan','Type','Mode','Status','Reason','Speed','Port Ch#'],'Interface')
    intDict={}

    if len(nve_interface_list):
        for interface in nve_interface_list:
            intf=normalizeInterfaceName(log,interface[0])
            intDict[intf] = {}
            intDict[intf]['Status'] = interface[1]
            intDict[intf]['Reason'] = interface[2]

    if len(interface_list):
        for interface in interface_list:
            intf=normalizeInterfaceName(log,interface[0])
            intDict[intf] = {}
            intDict[intf]['Vlan'] = interface[1]
            intDict[intf]['Type'] = interface[2]
            intDict[intf]['Mode'] = interface[3]
            intDict[intf]['Status'] = interface[4]
            intDict[intf]['Reason'] = interface[5]
            intDict[intf]['Speed'] = interface[6]
            intDict[intf]['Port Ch#'] = interface[7]

    if len(po_interface_list):
        for interface in po_interface_list:
            intf=normalizeInterfaceName(log,interface[0])
            intDict[intf] = {}
            intDict[intf]['Vlan'] = interface[1]
            intDict[intf]['Type'] = interface[2]
            intDict[intf]['Mode'] = interface[3]
            intDict[intf]['Status'] = interface[4]
            intDict[intf]['Reason'] = interface[5]
            intDict[intf]['Speed'] = interface[6]
            intDict[intf]['Protocol'] = interface[7]
   
    if len(monitor_list):
        for interface in monitor_list:
            intf=normalizeInterfaceName(log,interface[0])
            intDict[intf] = {}
            intDict[intf]['Vlan'] = interface[1]
            intDict[intf]['Type'] = interface[2]
            intDict[intf]['Mode'] = interface[3]
            intDict[intf]['Status'] = interface[4]
            intDict[intf]['Reason'] = interface[5]
            intDict[intf]['Speed'] = interface[6]
            intDict[intf]['Port Ch#'] = interface[7]
    if len(mgmt_interface_list):
        for interface in mgmt_interface_list:
            intf=normalizeInterfaceName(log,interface[0])
            intDict[intf] = {}
            intDict[intf]['VRF'] = interface[1] 
            intDict[intf]['Status'] = interface[2]
            intDict[intf]['IP Address'] = interface[3] 
            intDict[intf]['Speed'] = interface[4] 
            intDict[intf]['MTU'] = interface[5] 
    if len(tunnel_interface_list):
        for interface in tunnel_interface_list:
            intf=normalizeInterfaceName(log,interface[0])
            intDict[intf] = {}
            intDict[intf]['Status'] = interface[1]
            intDict[intf]['IP Address'] = interface[2] 
            intDict[intf]['Encap type'] = interface[3] 
            intDict[intf]['MTU'] = interface[4] 

    if len(loopback_interface_list):
        for interface in loopback_interface_list:
            intf=normalizeInterfaceName(log,interface[0])
            intDict[intf] = {}
            intDict[intf]['Status'] = interface[1]
            intDict[intf]['description'] = interface[2]

    if len(svi_interface_list):
        for interface in svi_interface_list:
            intf=normalizeInterfaceName(log,interface[0])
            intDict[intf] = {}
            intDict[intf]['Secondary VLAN(Type)'] = interface[1] 
            intDict[intf]['Status'] = interface[2]
            intDict[intf]['Reason'] = interface[3]

    #log.debug("Interface Dictionary " + str(intDict))
    return intDict

def unshutAllInterfaces(hdl):
    out=hdl.execute('show interface brief')
    hdl.execute('conf')
    for line in out.split('\n'):
        match=re.search('^(Eth[^ \t]+)',line)
        if match:
            if match.group(1)=='Ethernet':
                continue
            hdl.execute('int {0}'.format(match.group(1)))
            hdl.execute('no shut')

def shutAllInterfaces(hdl):
    out=hdl.execute('show interface brief')
    hdl.execute('conf')
    for line in out.split('\n'):
        match=re.search('^(Eth[^ \t]+)',line)
        if match:
            if match.group(1)=='Ethernet':
                continue
            hdl.execute('int {0}'.format(match.group(1)))
            hdl.execute('shut')


def getInterfaceUpList(hdl,log):

    # Returns all the interface names with status = up
    interfaceDict = getInterfaceBriefDict(hdl,log)
    upInterfaces = []
    for key in interfaceDict.keys():
        if re.match("Up", interfaceDict[key]['Status'], flags=re.I):
            upInterfaces.append(key)

    #log.debug("Interface Up list " + str(upInterfaces))
    return upInterfaces

def getSwitchName(hdl,log):
    """Method to return switchname"""

    return hdl.execute('show switchname')


def getNxosVersion(hdl,log):

    # Returns Nxos version
    showOutput=hdl.execute("show version")
    switchversion=re.findall("NXOS:\s+version\s+([0-9\.\(\)a-zA-Z]+)",showOutput,flags=re.I)
    if not switchversion:
            switchversion=re.findall("system:\s+version[ \t]*([0-9\.\(\)a-zA-Z]+)",showOutput,flags=re.I)
    log.debug("switch name " + switchversion[0])
    return switchversion[0]


def getFeaturesDict(hdl,log):

    # Returns dictionary of features with feature name as first level key
    #   instance, state as second level key
    showOutput=hdl.execute("show feature")
    featureList=re.findall("([a-zA-Z_]+)[ \t]*([0-9]+)[ \t]*([a-zA-Z]+)",showOutput,re.M | re.I)
    featureDict=convertListToDict(featureList,['feature','instance','state'],'feature')
    log.debug("Feature dictionary " + str(featureDict))
    return featureDict

def getArpEntryCount(hdl,log,*args):

    # Returns Arp Entry count for the given arg options
    arggrammar={}
    arggrammar['vrf'] = ''
    arggrammar['static'] = '-type bool'
    arggrammar['dynamic'] = '-type bool'

    command="show ip arp "
    staticCommand="show ip arp static"

    argOptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if argOptions.static:
        command = command + "static " 

    if argOptions.vrf:
        command = command + "vrf " + argOptions.vrf + " "
        staticCommand = staticCommand + " vrf " + argOptions. vrf + " "

    command = command + " | include Total"
    staticCommand = staticCommand + " | include Total"

    showOutput=hdl.execute(command)
    count=0
    countList=re.findall("entries:[ \t]*([0-9]+)",showOutput,flags=re.I)
    if len(countList) == 1:
        count = int(countList[0])

    if argOptions.dynamic and count:
        showOutput=hdl.execute(staticCommand)
        staticCountList=re.findall("entries:[ \t]*([0-9]+)",showOutput,flags=re.I)
        if len(staticCountList) == 1:
            count = count - int(staticCountList[0])

    #log.debug("ARP entry count for args : " + str(count))
    return count
      
        
def getArpEntryDict(hdl,log,*args):

    # Returns Arp Entry dictionary for the given options
    #   ip address is first level key
    #   mac,age,interface are second level keys for dynamic entries
    #   mac,interface,phy _interface are second level keys for static entries
    arggrammar={}
    arggrammar['vrf'] = ''
    arggrammar['static'] = '-type bool'
    arggrammar['dynamic'] = '-type bool'

    command="show ip arp "
    argOptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
 
    # IP MAC Age Interface 
    pattern = "([0-9\.]+)[ \t]*([0-9:\-]+)[ \t]*([0-9a-fA-F\.:]+)[ \t]*([a-zA-Z0-9/]+)"
    if argOptions.static:
        command = command + "static " 
        pattern = "([0-9\.]+)[ \t]*([0-9a-fA-F\.:]+)[ \t]*([a-zA-Z0-9/]+)[ \t]*([a-zA-Z0-9/]+)"

    if argOptions.vrf:
        command = command + "vrf " + argOptions.vrf + " "

    showOutput=hdl.execute(command)
    arpEntryList=re.findall(pattern,showOutput,flags=re.I)

    if argOptions.static:
        arpEntryDict=convertListToDict(arpEntryList,['Address','Mac_Address','Interface','Phy_Interface'],'Address')
    else:
        arpEntryDict={}
        tempArpEntryDict=convertListToDict(arpEntryList,['Address','Age','Mac_Address','Interface'],'Address')
        for ip in tempArpEntryDict:
            if tempArpEntryDict[ip]['Age'] == '-':
               continue
            arpEntryDict[ip]=tempArpEntryDict[ip]

    #log.debug("ARP entry for args : " + str(arpEntryDict))
    return arpEntryDict



def getMacAddressTableCountDict (hdl,log,*args):

    # Returns dictionary with dynamic,static,secure,total as keys

    dynamic = 0
    static = 0
    secure = 0
    overlay = 0
    returnDict={}
    arggrammar={}
    arggrammar['vlan'] = '-type int'
    arggrammar['interface'] = ''
    command = "show mac address-table count " 
    argOptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if argOptions.vlan:
        command = command + "vlan " + str(argOptions.vlan)
    elif argOptions.interface:
        command = command + "interface " + str(argOptions.interface)

    showOutput = hdl.execute(command)

    dynamicList = re.findall("Dynamic Address Count:[ \t]*([0-9]+)",showOutput,flags=re.I) 
    staticList = re.findall("Static Address Count:[ \t]*([0-9]+)",showOutput,flags=re.I) 
    secureList = re.findall("Secure Address.*[ \t]+Count:[ \t]*([0-9]+)",showOutput,flags=re.I) 
    overlayList = re.findall("Overlay Address Count:[ \t]*([0-9]+)",showOutput,flags=re.I) 

    cmd = 'show mac address-table static | begin ----- | inc static | count'
    show_mac_static=hdl.execute(cmd)

    if re.search( '([0-9]+)', show_mac_static ):
        match=re.search( '([0-9]+)', show_mac_static )
        static_all=int(match.group(1))
    else:
        static_all=0

    if len(dynamicList) == 1:
        dynamic = int(dynamicList[0])
    if len(staticList) == 1:
        static = int(staticList[0])
    if len(secureList) == 1:
        secure = int(secureList[0])
    if len(overlayList) == 1:
        overlay = int(overlayList[0])
    total = dynamic + secure + overlay + static_all

    returnDict['dynamic']=dynamic
    returnDict['static']=static_all
    returnDict['static_user_defined']=static
    returnDict['secure']=secure
    returnDict['overlay']=secure
    returnDict['total']=total

    log.debug("Macaddress Table Count " + str(returnDict))   
 
    return returnDict

def getStaticMacAddressTableCount (hdl,log,*args):

    # Returns integer

    options = ""
    for arg in args:
        options = options + " " + arg
    macAddressTableCountDict = getMacAddressTableCountDict(hdl,log,options)
    count=macAddressTableCountDict['static']
    log.debug("Static MAC address Table count " + str(count))
    return count

def getDynamicMacAddressTableCount (hdl,log,*args):

    # Returns integer

    options = ""
    for arg in args:
        options = options + " " + arg
    macAddressTableCountDict = getMacAddressTableCountDict(hdl,log,options)
    count=macAddressTableCountDict['dynamic']
    log.debug("Dynamic MAC address Table count " + str(count))
    return count

#======================================================================================#
# getHAOperationalMode - Method to get HA operational mode
#
# mandatory args
#
# hdl - switch handle object from icon
# log - harness/python logging object
#
#======================================================================================#
def getHAOperationalMode( hdl, log):
    import re
    msg='Fetch HA Operational mode'
    log.info(msg)
    sw_cmd="show redundancy status | grep operational"
    output=hdl.execute(sw_cmd)
    ha_oper_mode = re.findall('operational\:[ \t]+(.+)\r',output,re.M)
    return ha_oper_mode[0]


#======================================================================================#
# getHAAdministrativeMode - Method to get HA Administrative mode
#
# mandatory args
#
# hdl - switch handle object from icon
# log - harness/python logging object
#
#======================================================================================#
def getHAAdministartiveMode( hdl, log):
    import re
    msg='Fetch HA Administrative mode'
    log.info(msg)
    sw_cmd="show redundancy status | grep administrative"
    output=hdl.execute(sw_cmd)
    ha_admin_mode = re.findall('administrative\:[ \t]+(.+)\r',output,re.M)
    return ha_admin_mode[0]


#======================================================================================#
# getVpcRole - Method to get Vpc role
#
# mandatory args
#
# hdl - switch handle object from icon
# log - harness/python logging object
#
#======================================================================================#
def getVpcRole( hdl, log):
    import re
    msg='Get vPC role of the DUT - primary/secondary/None'
    log.info(msg)
    sw_cmd="show vpc role | grep 'vPC role'"
    output=hdl.execute(sw_cmd)
    vpc_role = re.findall('vPC role[ \t]+\:[ \t]+(.+)\r',output,re.M)
    if vpc_role:
        if re.search('operational',vpc_role[0], re.I):
            log.info('Vpc role on {0} is {1}'.format(hdl.switchName, vpc_role[0].split()[2]))
            return vpc_role[0].split()[2]
        else:
            log.info('Vpc role on {0} is {1}'.format(hdl.switchName, vpc_role[0].split()[0]))
            return vpc_role[0].split()[0]
    else:
        return ''

#======================================================================================#
# getVpcDomainId - Method to get Vpc Domain Id
#
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#======================================================================================#
def getVpcDomainId( hdl, log):
    msg='Get vPC Domain Id of the DUT'
    log.info(msg)
    sw_cmd="show vpc | grep 'vPC domain id'"
    output=hdl.execute(sw_cmd)
    vpc_domain_id = re.findall('vPC domain id[ \t]+\:[ \t]+([0-9]+).*\r',output,re.M)
    if vpc_domain_id:
        log.info('Vpc Domain Id on {0} is {1}'.format(hdl.switchName, vpc_domain_id[0]))
        return vpc_domain_id[0]
    else:
        return ''





#======================================================================================#

def getIpPathCount( hdl, log, *args):

    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,'namespace')
    pat_str="Total number of paths:"
    total_output=''
    if ns.vrf:
        log.info('Using vrf passed by user - {0}'.format(ns.vrf))
        vrflist=strtolist(ns.vrf)
        for eachvrf in vrflist:
            sw_cmd= 'show ip route summary vrf {0}'.format(eachvrf)
            pat='{0}[ ]*([.\0-9]+)\r\n'.format(pat_str)
            msg='Get Ip Route Count'
            log.info(msg)
            sw_cmd='show ip route summary vrf {0} | incl "{1}"'.format(eachvrf, pat_str)
            output=hdl.execute(sw_cmd)
            total_output=str(output)+'\r\n'+str(total_output)
                    
    else:
        sw_cmd='show ip route summary | incl "{0}"'.format(pat_str)
        total_output=hdl.execute(sw_cmd)

    route_path=0
    pat=':[ \t]+([0-9]+)'
    ip_route_path = re.findall(pat,total_output,re.M)
    if ip_route_path:
        for path in ip_route_path:
            route_path=route_path+int(path)
    else:
        return 0
    log.info('Ip route path is {0}'.format(route_path))
    return route_path

#======================================================================================#

def getIpv6PathCount( hdl, log, *args):

    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,'namespace')
    pat_str="Total number of paths:"
    total_output=''
    if ns.vrf:
        log.info('Using vrf passed by user - {0}'.format(ns.vrf))
        vrflist=strtolist(ns.vrf)
        for eachvrf in vrflist:
            sw_cmd= 'show ipv6 route summary vrf {0}'.format(eachvrf)
            pat='{0}[ ]*([.\0-9]+)\r\n'.format(pat_str)
            msg='Get Ip Route Count'
            log.info(msg)
            sw_cmd='show ipv6 route summary vrf {0} | incl "{1}"'.format(eachvrf, pat_str)
            output=hdl.execute(sw_cmd)
            total_output=str(output)+'\r\n'+str(total_output)
                    
    else:
        sw_cmd='show ipv6 route summary | incl "{0}"'.format(pat_str)
        total_output=hdl.execute(sw_cmd)

    route_path=0
    pat=':[ \t]+([0-9]+)'
    ip_route_path = re.findall(pat,total_output,re.M)
    if ip_route_path:
        for path in ip_route_path:
            route_path=route_path+int(path)
    else:
        return 0
    log.info('Ip route path is {0}'.format(route_path))
    return route_path





#=====================================================================================#
# getIpRouteCount - Method to get Ip route count
#
# mandatory args
#
# hdl - switch handle object from icon
# log - harness/python logging object
#
# optional args
#
# vrf - vrf name to get Ip route count in non-default vrf 
# protocol - protocol name to get route count of particular type/protocol
#            acceptable values are "hsrp","ospf","direct","local","am",
#                 "bgp","eigrp","broadcast","rip","vrrp"
#======================================================================================#
def getIpRouteCount( hdl, log, *args):

    arggrammer={}
    arggrammer['vrf']='-type str'
    arggrammer['protocol']='-type str -subset ["hsrp","ospf","direct","local","am","bgp","eigrp","broadcast","rip","vrrp","static","discard"]'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,'namespace')
    pat_str="Total number of routes:"
    total_output=''
    if ns.vrf:
        log.info('Using vrf passed by user - {0}'.format(ns.vrf))
        vrflist=strtolist(ns.vrf)
        for eachvrf in vrflist:
            sw_cmd= 'show ip route summary vrf {0}'.format(eachvrf)
            pat='{0}[ ]*([.\0-9]+)\r\n'.format(pat_str)
        
            if ns.protocol:
                protocol_list=strtolist(ns.protocol)
                for proto in protocol_list:
                    sw_cmd='show ip route summary vrf {0}'.format(eachvrf)
                    log.info('Using protocol passed by user {0}'.format(proto))
                    sw_cmd= sw_cmd + " | incl " + proto
                    pat=r'{0}[-0-9]*[ \t]+:[ \t]+([0-9]+)'.format(proto)
                    output=hdl.execute(sw_cmd)
                    lines = output.split('\n')
                    for line in lines:
                       match = re.search(pat, line)
                       if match:
                          total_output=str(match.group(0))+'\r\n'+str(total_output)
            else: 
                msg='Get Ip Route Count'
                log.info(msg)
                sw_cmd='show ip route summary vrf {0} | incl "{1}"'.format(eachvrf, pat_str)
                output=hdl.execute(sw_cmd)
                total_output=str(output)+'\r\n'+str(total_output)
                    
    elif ns.protocol:
        for proto in ns.protocol.split(','):
            pat='{0}.*[ ]+:[ ]+([\.0-9]*)'.format(proto)
            sw_cmd='show ip route summary | incl {0}'.format(proto)
            pat=r'{0}[-0-9]*[ \t]+:[ \t]+([0-9]+)'.format(proto)
            output=hdl.execute(sw_cmd)
            lines = output.split('\n')
            for line in lines:
               match = re.search(pat, line)
               if match:
                  total_output=str(match.group(0))+'\r\n'+str(total_output)
            
    else:
#        pat='{0}[ ]*([.\0-9]+)\r\n'.format(pat_str)
        pat="Total number of routes:[ \t]+([0-9]+)"
        sw_cmd='show ip route summary | incl "{0}"'.format(pat_str)
        output=hdl.execute(sw_cmd)
        match = re.search(pat, output)
        if match:
           total_output = match.group(0)
    route_count=0
    pat=':[ \t]+([0-9]+)'
    ip_route_count = re.findall(pat,total_output,re.M)
    if ip_route_count:
        for route in ip_route_count:
            route_count=route_count+int(route)
    else:
        return 0
    log.info('Ip route count is {0}'.format(route_count))
    return route_count



def getLineCardDict(hdl, log, *args):

    #Returns dictionary with mod as a key
    #Dictionary of ('status','model','type','ports') as value. e.g.
    #'3': {'status': 'ok', 'model': 'N7K-F248XT-25', 'type': '1/10 Gbps BASE-T Ethernet Module', 'ports': '48'}, 
    #'4': {'status': 'ok', 'model': 'N7K-F248XT-25', 'type': '1/10 Gbps BASE-T Ethernet Module', 'ports': '48'}}

    msg='Fetch list of line card modules on {0}'.format(hdl.switchName)
    log.info(msg)
    arggrammer={}
    arggrammer['module']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,'namespace')
    mod=''
    if ns.module:
        mod=ns.module

    sw_cmd="show module "+mod
    show_mod=hdl.execute(sw_cmd)
    # This needs to be change for EOR 
    if (hdl.device_type == 'N3K'):
        #pat ='(\d+)\s+(\d+)\s+(\S+\s\S+)\s+(\S+)\s+(\S+)'
        pat = '(\d+)\s+(\d+)\s+(.* Supervisor)\s+(\S+)\s+(\S+)'
    else:
        pat='([0-9]+) +([0-9]+) +({2}) +({0}) +({1})'.format(rex.LC_MODEL,rex.LC_STATUS,rex.LC_MODULE_TYPE)

#    pat='([0-9]+) +([0-9]+) +({2}) +({0}) +({1})'.format(rex.LC_MODEL,rex.LC_STATUS,rex.LC_MODULE_TYPE)
    mod_list=re.findall( pat, show_mod, flags=re.I )
    mod_dict=convertListToDict(mod_list,['Mod','Ports','Module-Type','Model','Status'],'Mod')
    if len(mod_list)==0:
         msg='No Line Card Module was found on {0}'.format(hdl.switchName)
         print(msg)
         log.info(msg)
    return mod_dict

def oldgetFabricCardDict(hdl, log):

    #Returns dictionary with fab mod as key
    #Dictionary of ('status','model','type','ports') as value. e.g.
    #{'1': {'status': 'ok', 'model': 'N7K-C7009-FAB-2', 'type': 'Fabric Module 2', 'ports': '0'},
    # '3': {'status': 'ok', 'model': 'N7K-C7009-FAB-2', 'type': 'Fabric Module 2', 'ports': '0'},
    # '2': {'status': 'ok', 'model': 'N7K-C7009-FAB-2', 'type': 'Fabric Module 2', 'ports': '0'}}


    msg='Fetch list of fabric card modules on {0}'.format(hdl.switchName)
    log.info(msg)
    sw_cmd="show module fabric"
    show_fab=hdl.execute(sw_cmd)
    # This needs to be change for EOR 
    pat='([0-9]+) +([0-9]+) +({2}) +({0}) +({1})'.format(rex.FC_MODEL,rex.LC_STATUS,rex.FC_MODULE_TYPE)
    fab_list=re.findall( pat, show_fab, flags=re.I )
    fab_dict=convertListToDict(fab_list,['Xbar','Ports','Type','Model','Status'],'Xbar')
    if len(fab_list)==0:
         msg='No Fabric Card Module was found on {0}'.format(hdl.switchName)
         print(msg)
         log.info(msg)
    return fab_dict



def getFabricCardDict( hdl, log, *args ):

    arggrammar={}
    arggrammar['status']='-type str -default all'
    ns=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

    show_version=hdl.execute('show version')
    if re.search( 'Nexus9000|C900|EOR', show_version, re.I ):
        model='N9K'
    elif re.search( 'Nexus7000|C700', show_version, re.I ):
        model='N7K'
    else:
        model='N9K'

    if re.search( 'all', ns.status, re.I ):
        if re.search( 'N9K', model, re.I ):
            cmd='show module | grep FM'
        else:
            cmd='show module fabric '
    else:
        if re.search( 'N9K', model, re.I ):
            cmd='show module | grep FM | grep {0}'.format(ns.status)
        else:
            cmd='show module fabric | grep {0}'.format(ns.status)

    show_mod=hdl.execute(cmd)
    pattern='({0})\s+({0})\s+([a-zA-Z0-9\-\_ ]+)\s+([a-zA-Z0-9\-\_]+)\s+([a-zA-Z\-]+)'.format(rex.DECIMAL_NUM)
    n7k_patt='({0})\s+({0})\s+([a-zA-Z0-9\-\_]+)\s+([a-zA-Z0-9\-\_]+)\s+({0})\s+([a-zA-Z0-9\-\_]+)\s+([a-zA-Z]+)'.format(rex.DECIMAL_NUM)
    if re.search( 'N9K', model, re.I ):
        match_list=re.findall( pattern, show_mod, re.I )
    else:
        match_list=re.findall( n7k_patt, show_mod, re.I )

    fabric_dict=convertListToDict( match_list, [ 'Mod', 'Ports', 'Module-Type', 'Model', 'Status' ], ['Mod'] )

    return fabric_dict

def getSystemCardDict( hdl, log, *args ):

    arggrammar={}
    arggrammar['status']='-type str -default all'
    ns=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

    show_version=hdl.execute('show version')
    if re.search( 'Nexus9000|C900|EOR', show_version, re.I ):
        model='N9K'
    else:
        model='N9K'

    if re.search( 'all', ns.status, re.I ):
        if re.search( 'N9K', model, re.I ):
            cmd='show module | grep SC'
    else:
        if re.search( 'N9K', model, re.I ):
            cmd='show module | grep FM | grep {0}'.format(ns.status)

    show_mod=hdl.execute(cmd)
    pattern='({0})\s+({0})\s+([a-zA-Z0-9\-\_ ]+)\s+([a-zA-Z0-9\-\_]+)\s+([a-zA-Z\-]+)'.format(rex.DECIMAL_NUM)
    if re.search( 'N9K', model, re.I ):
        match_list=re.findall( pattern, show_mod, re.I )

    sc_dict=convertListToDict( match_list, [ 'Mod', 'Ports', 'Module-Type', 'Model', 'Status' ], ['Mod'] )

    return sc_dict
 

 
def getLineCardModel(hdl, log, lc):

    #Returns the line card model

    msg='Fetch line card on mod {0} on switch {1}'.format(lc,hdl)
    log.info(msg)
    sw_cmd="show module {0}".format(lc)
    show_mod=hdl.execute(sw_cmd)
    pat='{0} +[0-9]+ +({3}) +({1}) +({2})'.format(lc,rex.LC_MODEL,rex.LC_STATUS,rex.LC_MODULE_TYPE)
    model_val= re.search(pat,show_mod,flags=re.I).group(2)
    log.info('line card model on module {0} is {1} on switch {2}'.format(lc,model_val,hdl))
    return model_val
 

def getVlanToBDDict(hdl, log, *args):

    # This function will take vlan as input and return vlan, bd mapping in the form of a dictionary
    # The bd value for any vlan can be accessed by passing vlan as key
    # vlan is required parameter
    arggrammar={}
    arggrammar['vlan']='-type str -required True' 
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    vlan = getattr(parse_output,'vlan')    
    if vlan == 'all':
        cmd='show vlan internal bd-info vlan-to-bd all-vlan'
    else:
        try:
            vlan = int(vlan)
        except ValueError:
            log.error('Expected integer for vlan and found:' + vlan)
            return -1
        cmd='show vlan internal bd-info vlan-to-bd ' +  str(vlan)
    #Get the output from switch
    cmd_out=hdl.execute(cmd)
    bd_matchlist=re.findall('[0-9]+ +([0-9]+) +([0-9]+)', cmd_out)
    return convertListToDict(bd_matchlist,['vlan','bd'],'vlan')


def getBDToVlanDict(hdl, log, *args):

    # This function will take bd as input and return bd, vlan mapping in the form of a dictionary
    # The vlan value for any bd can be accessed by passing bd as key
    # bd is required parameter
    arggrammar={}
    arggrammar['bd']='-type str -required True' 
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    bd = getattr(parse_output,'bd')    
    if bd == 'all':
        cmd='show vlan internal bd-info bd-to-vlan all-bd'
    else:
        try:
            bd = int(bd)
        except ValueError:
            log.error('Expected integer for bd and found:' + bd)
            return -1
        cmd='show vlan internal bd-info bd-to-vlan ' +  str(bd)
    #Get the output from switch
    cmd_out=hdl.execute(cmd)
    bd_matchlist=re.findall('[0-9]+ +([0-9]+) +([0-9]+)', cmd_out)
    return convertListToDict(bd_matchlist,['bd','vlan'],'bd')

def getHardwareMacTableDict(hdl,log,*args):

    # Get the Hardware MAC address table fields in dict format. The keys are fe,mac,bd

    #Dict[('0', '0022.bdf2.43c8', '10')] = 0
    #Dict[('0', '0022.bdf2.43c8', '5')] = 0 
    #Dict[('0', '0000.1003.0001', '3')] = 0 
    #Dict[('0', '0000.3009.0001', '9')] = 0 
    #Dict[('0', '0022.bdf2.43c8', '4')] = 0 
    #Dict[('0', '0022.bdf2.43c8', '1')] = 0 
    #Dict[('0', '0000.3002.0001', '2')] = 0 
    #Dict[('0', '0000.1008.0001', '8')] = 0 
    #Dict[('0', '0000.0000.2222', '4043')] = 1

    arggrammar={}
    arggrammar['module']='-type int -required True' 
    arggrammar['address']='-type str'
    arggrammar['flag']='-type str -choices ["dynamic","static"]'
    arggrammar['intf']='-type str'
    arggrammar['vlan']='-type int'
    arggrammar['cmd_on_module']='-type bool -default False'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    cmd = 'show hardware mac address-table ' + str(getattr(parse_output,'module'))
    if getattr(parse_output,'flag'):
        cmd = cmd + ' ' +  getattr(parse_output,'flag')
    if getattr(parse_output,'vlan'):
        cmd = cmd + ' vlan ' + str(getattr(parse_output,'vlan'))
    if getattr(parse_output,'intf'):
        cmd = cmd + ' interface ' + getattr(parse_output,'intf')
    if getattr(parse_output,'address'):
        cmd = cmd + ' address ' + getattr(parse_output,'address')
    if parse_output.cmd_on_module:
        mac_table=hdl.execute(cmd, '-module {0}'.format(parse_output.module))
    else:
        mac_table=hdl.execute(cmd)
    #Get the pattern definition constructed
    ig1 = '[0-9A-Za-z]+'
    ig2 = '[0-9]+'
    if (hdl.device_type == "EOR"):
        #PI column will be removed later
        pattern = '({0})\s+{1}\s+({0})\s+({2})\s+{0}\s+{0}\s+{0}\s+{0}\s+({1})\s+{1}\s+{1}\s+{1}\s+{1}'\
            .format(rex.NUM,rex.BOOL,rex.MACADDR)
    else:
        pattern = '({0})\s+{1}\s+{1}\s+({0})\s+({2})\s+{3}\s+({1})\s+{3}\s+{4}\s+{0}\s+{4}\s+{0}'\
            .format(rex.NUM,rex.BOOL,rex.MACADDR,ig1,ig2)
    mac_matchlist=re.findall(pattern,mac_table)
    return convertListToDict(mac_matchlist,['fe','bd','mac','mac_type'],['fe','mac','bd'])


def getHardwareMacTableCount(hdl,log,*args):

    # Get the Hardware MAC address table fields in dict format. The keys are fe,mac,bd
    # fe  mac              bd    ntfy   age   mac_type   sec   gm   pi   
    # 2   a8c7.7c5a.516a   165   0      168   0          0     0    0    
    # 2   7ccf.ddaf.4fde   165   0      168   0          0     0    0    
    # 2   5829.beaa.d799   165   0      168   0          0     0    0    
    # 2   6496.cf19.c613   165   0      168   0          0     0    0    

    arggrammar={}
    arggrammar['module']='-type int -required True' 
    arggrammar['address']='-type str'
    arggrammar['flag']='-type str -choices ["dynamic","static"]'
    arggrammar['intf']='-type str'
    arggrammar['vlan']='-type int'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    cmd = 'show hardware mac address-table ' + str(getattr(parse_output,'module'))
    if getattr(parse_output,'flag'):
        cmd = cmd + ' ' +  getattr(parse_output,'flag')
    if getattr(parse_output,'vlan'):
        cmd = cmd + ' vlan ' + str(getattr(parse_output,'vlan'))
    if getattr(parse_output,'intf'):
        cmd = cmd + ' interface ' + getattr(parse_output,'intf')
    if getattr(parse_output,'address'):
        cmd = cmd + ' address ' + getattr(parse_output,'address')
    cmd = cmd + ' | wc lines '
    output=hdl.execute(cmd)
    #Get the pattern definition constructed
    pattern = rex.NUM 
    #print ('pattern=' + pattern)
    count=re.findall(pattern,output)
    #print(mac_matchlist)
    #return convertListToDict(mac_matchlist,['fe','pi','bd','mac','mac_type','age','gm','sec','ntfy'],['fe','mac','bd'])
    return count[0]        

def printDict (dict,keys=None):

    if not keys:
       keys = dict.keys()
       for key in keys:
           print ("Dict[{0}] = {1}".format(key,dict[key]))
    else:
       header=[]
       colmaxlengths = {}
       for key in keys:
           header.append(key)
           for i in range(100):
               colmaxlengths[i] = 0

       lines = []
       columns = False
       for key in dict.keys():
           line = []
           col=0
           if "startswith" in dir(key):
               subkeys=key.split()
           else:
               subkeys=key
           for subkey in subkeys:
               line.append(subkey)
               if len(subkey) > colmaxlengths[col]:
                   colmaxlengths[col]=len(subkey) 
               col=col+1
           for column in dict[key].keys():
               line.append(dict[key][column])
               if len(dict[key][column]) > colmaxlengths[col]:
                   colmaxlengths[col] = len(dict[key][column])
               if not columns:
                  header.append(column)
                  if len(column) > colmaxlengths[col]:
                   colmaxlengths[col] = len(column)
               col=col+1
           columns=True
           lines.append(line)

       col=0
       for element in header:
           #print element," " * (colmaxlengths[col] - len(element) + 1),
           col=col+1
       #print ""
       for line in lines:
           col=0
           for element in line:
               #print element," " * (colmaxlengths[col] - len(element) + 1),
               col=col+1
           #print "" 




#======================================================================================#
# getIpOspfNeighborDict - Method to get Ip OSPF neighbors
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
# optional args
# CLI accepts only one of the optional arguments - vrf or interface
# vrf - vrf name to get Ip ospf neighbor dict in non-default vrf 
# interfaces - physical or vlan or port-channel
#              Example: '-interface vlan20' or 'interface eth3/1' or
#                       '-vrf test'  or '-interface po10'
#======================================================================================#
def getIpOspfNeighborDict(hdl,log,*args):
        arggrammer={}
        arggrammer['vrf']='-type str'
        arggrammer['interface']=' -type str'
        arggrammer['mutualExclusive'] =[('vrf','interface')]
        ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
        sw_cmd="show ip ospf neighbors  "
        IP_ADDR='[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
        if ns.vrf:
              sw_cmd=sw_cmd + "vrf " + ns.vrf
        if ns.interface:
            sw_cmd= sw_cmd + " " + str(ns.interface)

        output=hdl.execute(sw_cmd)
        pat='({0})[ \t]+([0-9]+)[ \t]([A-Z]+)\/[ ]*([^ ]+)[ \t]+({1})[ \t]+({0})[ \t]+([^ \t]+)'.format(IP_ADDR,rex.UPTIME) 
        neighbor_list=re.findall( pat, output, flags=re.M )
        neighbor_dict=convertListToDict(neighbor_list,['Neighbor_ID','Pri','Adj','State','Up_Time','Address','Interface'],['Address'])
        if len(neighbor_list)==0:
             msg='No IP ospf neighbors found on {0}'.format(hdl.switchName)
             print(msg)
             log.info(msg)
        return neighbor_dict

def getLineCardStatus(hdl, log, lc):

    #Returns the line card status

    msg='Fetch line card status on mod {0} on switch {1}'.format(lc,hdl)
    log.info(msg)
    sw_cmd="show module {0}".format(lc)
    show_mod=hdl.execute(sw_cmd)
    pat='{0} +[0-9]+ +({3}) +({1}) +({2})'.format(lc,rex.LC_MODEL,rex.LC_STATUS,rex.LC_MODULE_TYPE)
    model_val= re.search(pat,show_mod,flags=re.I).group(3)
    log.info('line card model on module {0} is {1} on switch {2}'.format(lc,model_val,hdl))
    return model_val

def getSnmpHostDict(hdl, log):

    #Returns the dictionary of snmp host with ('host','port','version') as key
    #'level','type','secname' as second level keys e.g.
    #{('172.28.23.40', '100', 'v2c'): {'type': 'trap', 'secname': 'private', 'level': 'noauth'},
    #('172.28.23.40', '101', 'v2c'): {'type': 'inform', 'secname': 'public', 'level': 'noauth'}, 
    #('172.28.23.40', '162', 'v3'): {'type': 'trap', 'secname': '345', 'level': 'auth'}}

    msg='Fetch snmp host info on switch {0}'.format(hdl.switchName) 
    log.info(msg)
    sw_cmd='show snmp host'
    show_snmp=hdl.execute(sw_cmd)
    host='[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
    port='[0-9]+'
    version='v1|v2c|v3'
    level='auth|noauth|priv'
    type='trap|inform'
    secname='[^ ]+'
    pattern='({0}) +({1}) +({2}) +({3}) +({4}) +({5})'.format(host,port,version,level,type,secname)
    hosts=re.findall(pattern,show_snmp,re.I) 
    hosts_dict=convertListToDict(hosts,['host','port','version','level','type','secname'],['host','port','version'],'tuple')
    if len(hosts)==0:
         msg='No snmp host was found on {0}'.format(hdl.switchName)
         print(msg)
         log.info(msg)
    return hosts_dict

def getUnwrappedBuffer(buffer,delimiter=" "):

    # Returns a string
    # If output has wrapped lines as follows (port-channel summary)
    # "21    Po21(SU)    Eth      NONE      Eth2/11(P)   Eth2/12(D)
    #  22    Po22(SU)    Eth      NONE      Eth1/1(P)    Eth1/2(P)    Eth1/3(P)
    #                                       Eth1/4(P)
    #  101   Po101(SD)   Eth      NONE      Eth2/1(D)    Eth2/2(D)"
    # This converts to
    # "21    Po21(SU)    Eth      NONE      Eth2/11(P)   Eth2/12(D)
    #  22    Po22(SU)    Eth      NONE      Eth1/1(P)    Eth1/2(P)    Eth1/3(P) Eth1/4(P)
    #  101   Po101(SD)   Eth      NONE      Eth2/1(D)    Eth2/2(D)"
    #
    # This helps to write get procedures with everyoutput being a single line 
    # and makes regular expressions seamless independent of wrapped output

    previousline=""
    lines=[]
    returnbuffer = ""
    buffer=re.sub("\r","",buffer)
    for line in buffer.split("\n"):
        wrappedline=re.findall("^[ \t]+(.*)",line,flags=re.I)
        if len(wrappedline) > 0:
           previousline = previousline + delimiter + re.sub("\r\n","",wrappedline[0])
        else:
           if (previousline != ""):
               returnbuffer = returnbuffer + previousline + "\n"
           previousline=re.sub("[\r\n]+","",line)
    if (previousline != ""):
          returnbuffer = returnbuffer + previousline + "\n"
    return returnbuffer


def getCdpNeighborDict(hdl,log,*args):

    # Returns CDP neighbor dict (peerdevice,localinterface,peerport)
    #   is the frist level key. hldtime, capability,peerplatform
    #   are the second level keys
    # Takes -interface as an additional argument

    arggrammar={}
    arggrammar['interface']='-type str'
    cmd = "show cdp neighbors " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    showoutput = hdl.execute(cmd)
    
    pattern="([a-zA-Z0-9\(\)\-_]+)" # Peer device
    pattern=pattern+"[ \t]+([^ \t]+)" # local interface 
    pattern=pattern+"[ \t]+([0-9]+)" # Hold time
    pattern=pattern+"[ \t]+([BDHIRSTVrs ]+)" # capability
    pattern=pattern+"[ \t]+(.*)[ \t]+({0})".format(rex.INTERFACE_NAME) # Peer platform
    #pattern=pattern+"[ \t]+([^ \t]+)" # Peer platform
    #pattern=pattern+"[ \t]+([^ \t]+)" # Peer Port ID
    cdpneighborlist=re.findall(pattern,getUnwrappedBuffer(showoutput),flags=re.I|re.M)
    cdpneighbordict=convertListToDict(cdpneighborlist,['peerdevice','localinterface','hldtime','capability','peerplatform','peerport'],['localinterface'])
    log.debug("CDP Neighbor Dict " + str(cdpneighbordict))
    return cdpneighbordict


def getCdpNeighborCount(hdl,log,*args):

    # Returns CDP neighbor dict (peerdevice,localinterface,peerport)
    #   is the frist level key. hldtime, capability,peerplatform
    #   are the second level keys
    # Takes -interface as an additional argument

    arggrammar={}
    arggrammar['interface']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    count=0
    if ns.interface:
        intlist=normalizeInterfaceName(log,strtoexpandedlist(ns.interface))
        for int in intlist:
            cdpdict=getCdpNeighborDict(hdl, log, '-interface {0}'.format(int))
            count+=len(cdpdict.keys())
    else:
        cdpdict=getCdpNeighborDict(hdl, log)
        count=len(cdpdict.keys())
        
    log.info('Cdp neighbor count is {0}'.format(count))
    return count
    


def getCdpNeighborList(hdl,log,*args):

    # Returns CDP neighbor dict (peerdevice,localinterface,peerport)
    #   is the frist level key. hldtime, capability,peerplatform
    #   are the second level keys
    # Takes -interface as an additional argument
    arggrammar={}
    arggrammar['interface']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    returnlist = []
    if ns.interface:
        intlist=normalizeInterfaceName(log,strtoexpandedlist(ns.interface))
        for int in intlist:
            cdpdict=getCdpNeighborDict(hdl, log, '-interface {0}'.format(int))
            returnlist.append(cdpdict[int]['peerdevice'].split('(')[0])
    else:
        cdpdict=getCdpNeighborDict(hdl, log)
        for key in cdpdict.keys():
            returnlist.append(cdpdict[key]['peerdevice'].split('(')[0])           
    ## Get unique neighbors
    nei_set=set(returnlist)
    cdplist=list(nei_set)
    log.debug("CDP Neighbor List  " + str(cdplist))
    return cdplist   
    
      
def getSyslogServerDict(hdl,log):

    # Returns syslog server dictionary serverip is first level key
    # severity, facility VRF are the second level keys
    
    showoutput = hdl.execute("show logging server")
    pattern="\{("+rex.IPv4_ADDR+")"
    pattern="\{("+rex.IPv4_ADDR+"|"+rex.IPv6_ADDR+")"

    pattern=pattern+"\}.*everity:[ \t]+("+rex.ALPHANUM+")"
    pattern=pattern+".*acility:[ \t]+("+rex.ALPHANUM+")"
    pattern=pattern+".*VRF:[ \t]+([a-zA-Z0-9_\-]+)" 
    logserverlist=re.findall(pattern,getUnwrappedBuffer(showoutput),flags=re.I|re.M)
    logserverdict=convertListToDict(logserverlist,['serverip','severity','facility','vrf'],['serverip'])
    log.debug("Logging servers : " + str(logserverdict))
    return logserverdict

def getSyslogServerList(hdl,log): 

    # Returns syslog server list
    
    logserverdict = getSyslogServerDict(hdl,log)
    logserverlist = logserverdict.keys()
    log.debug("Logging servers : " + str(logserverlist))
    return logserverlist



#======================================================================================#
# getIpv6RouteCount - Method to get Ipv6 route count
#
# mandatory args
#
# hdl - switch handle object from icon
# log - harness/python logging object
#
# optional args
#
# vrf - vrf name to get Ip route count in non-default vrf 
# protocol - protocol name to get route count of particular type/protocol
#            acceptable values are "hsrpv6","ospfv3","direct","local","am","broadcast",
#                 "bgp","vrrpv3"
#======================================================================================#
def getIpv6RouteCount(hdl, log, *args):
    arggrammer={}
    arggrammer['vrf']='-type str'
    arggrammer['protocol']='-type str -subset ["discard","hsrp","ospfv3","direct","local","am","bgp","broadcast","vrrp","static"]'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,'namespace')
    pat_str="Total number of routes:"
    total_output=''
    if ns.vrf:
        log.info('Using vrf passed by user - {0}'.format(ns.vrf))
        vrflist=strtolist(ns.vrf)
        for eachvrf in vrflist:
            sw_cmd= 'show ipv6 route summary vrf {0}'.format(eachvrf)
            pat='{0}[ ]*([.\0-9]+)\r\n'.format(pat_str)
        
            if ns.protocol:
                protocol_list=strtolist(ns.protocol)
                for proto in protocol_list:
                    sw_cmd="show ipv6 route summary vrf {0}".format(eachvrf)
                    log.info('Using protocol passed by user {0}'.format(proto) )
                    sw_cmd= sw_cmd + " | incl " + proto
                    pat='{0}.*[ ]+:[ ]*([\.0-9]*)'.format(proto)
                    output=hdl.execute(sw_cmd)
                    total_output=str(output)+'\r\n'+str(total_output)
            else: 
                msg='Get Ipv6 Route Count'
                log.info(msg)
                sw_cmd='show ipv6 route summary vrf {0} | incl "{1}"'.format(eachvrf, pat_str)
                output=hdl.execute(sw_cmd)
                total_output=str(output)+'\r\n'+str(total_output)
                    
    elif ns.protocol:
        for proto in ns.protocol.split(','):
            pat='{0}.*[ ]+:[ ]+([\.0-9]*)'.format(proto)
            sw_cmd='show ipv6 route summary | incl {0}'.format(proto) 
            output=hdl.execute(sw_cmd)
            total_output=str(output)+'\r\n'+str(total_output)
    else:
#        pat='{0}[ ]*([\0-9]+)\r\n'.format(pat_str)
        sw_cmd='show ipv6 route summary | incl "{0}"'.format(pat_str)
        total_output=hdl.execute(sw_cmd)
    route_count=0
    pat=':[ \t]*([0-9]+)'
    ip_route_count = re.findall(pat,total_output,re.M)
    if ip_route_count:
        for route in ip_route_count:
            route_count=route_count+int(route)
    else:
        return 0
    log.info('Ipv6 route count is {0}'.format(route_count))
    return route_count

    
def getModuleListFromInterfaces(log, interfaces):
    
    #Returns module list based on the given interface names
   
    msg='Fetch module list based on interface names {0}'.format(interfaces)
    log.info(msg) 
    mod_list=[]
    for int in interfaces:
        print (int)
        mod=re.search('.*([0-9]+)\/[0-9]+',int)
        if (mod and mod.group(1) not in mod_list):
            mod_list.append(mod.group(1))
    return mod_list

def getBiosVersion(hdl,log):

    #Returns BIOS version

    msg='Fetch BIOS version on switch {0}'.format(hdl.switchName)
    log.info(msg)            
    sw_cmd='show version | inc BIOS'
    output=hdl.execute(sw_cmd)
    return re.findall('BIOS: +version +([0-9\.]+)',output,re.I)



def getInterfaceDict( hdl, log, *args ):

     """
     Return the output of show interface in dict format for all types of interfaces with every parameter listed in show interface.
     The interface name is the top level key.

     Usage : 
     getInterfaceDict( hdl, log )
     getInterfaceDict( hdl, log, '-interface_list eth3/2-3,eth4/1'

     Sample Output:
     {'Eth3/2': {'status': 'down', 'rxload': '1/255', 'bia': '0022.bdf5.14d0', 'hardware': '1000/10000 Ethernet', 'bandwidth': '10000000', 'reliability': '255/255', 'in_flow_control': 'off', 'in_bps': '0', 'resets': '0', 'speed': 'auto-speed', 'out_bps': '0', 'out_flow_control': 'off', 'txload': '1/255', 'rx': OrderedDict([('unicast_packets', '0'), ('multicast_packets', '0'), ('broadcast_packets', '0'), ('input_packets', '0'), ('input_bytes', '0'), ('jumbo_packets', '0'), ('storm_suppression_packets', '0'), ('runts', '0'), ('giants', '0'), ('crc', '0'), ('no_buffer', '0'), ('input_error', '0'), ('short_frame', '0'), ('overrun', '0'), ('underrun', '0'), ('ignored', '0'), ('watchdog', '0'), ('bad_etype_drop', '0'), ('bad_proto_drop', '0'), ('if_down_drop', '0'), ('input_with_dribble', '0'), ('input_discard', '0'), ('pause', '0')]), 'mac': '0022.bdf3.7b81', 'negotiation': 'on', 'mtu': '1500', 'delay': '10', 'monitor': 'off', 'in_pps': '0', 'tx': OrderedDict([('unicast_packets', '0'), ('multicast_packets', '0'), ('broadcast_packets', '0'), ('output_packets', '0'), ('output_bytes', '0'), ('jumbo_packets', '0'), ('output_error', '0'), ('collision', '0'), ('deferred', '0'), ('late_collision', '0'), ('lost_carrier', '0'), ('no_carrier', '0'), ('babble', '0'), ('output_discard', '0'), ('pause', '0')]), 'out_pps': '0'}}
      
     """
     arggrammar={}
     arggrammar['interface_list']='-type str'
     ns=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

     if ns.interface_list is not None:
         cmd='show interface {0}'.format(ns.interface_list)
     else:
         cmd='show interface'

     full_output=hdl.execute(cmd)

     dict={}

     per_intf_out_list=full_output.split('\r\n\r\n')

     for output in per_intf_out_list:
         if re.search( '^([0-9a-zA-Z\-\/]+)\s+is\s+', output, re.I ):
             match=re.search( '^([0-9a-zA-Z\-\/]+)\s+is\s+', output, re.I )
             intf_name=normalizeInterfaceName( log, match.group(1))
             print('the name of interface is {0}'.format(intf_name))
             dict[intf_name]={}
             int=re.findall('({0}) +is (up|down)'.format(rex.INTERFACE_NAME),output,re.I)
             if (len(int)==0):
                 return int
             dict[intf_name].update({'status':int[0][1]})
             hardware=re.findall('Hardware: +([0-9\/]+ [A-Za-z]+), +address: ({0}) +\(bia +({0})\)'.format(rex.MACADDR),output,re.I)
             hardware_no_bia=re.findall('Hardware is ([0-9A-Za-z]+), address is\s+({0})'.format(rex.MACADDR),output,re.I)
             if (hardware):
                 dict[intf_name].update({'hardware':hardware[0][0]})
                 dict[intf_name].update({'mac':hardware[0][1]})
                 dict[intf_name].update({'bia':hardware[0][2]})
             elif (hardware_no_bia):
                 dict[intf_name].update({'hardware':hardware_no_bia[0][0]})
                 dict[intf_name].update({'mac':hardware_no_bia[0][1]})

             if re.findall('MTU +([0-9]+) +bytes',output, re.I):
                 dict[intf_name].update({'mtu':re.findall('MTU +([0-9]+) +bytes',output, re.I)[0]})
             if re.findall('BW +([0-9]+) +kbit',output,re.I):
                 dict[intf_name].update({'bandwidth':re.findall('BW +([0-9]+) +kbit',output,re.I)[0]})
             if re.findall('DLY +([0-9]+) +usec',output,re.I):
                 dict[intf_name].update({'delay':re.findall('DLY +([0-9]+) +usec',output,re.I)[0]})
             if re.findall('reliability +([0-9]+\/[0-9]+)',output,re.I):
                 dict[intf_name].update({'reliability':re.findall('reliability +([0-9]+\/[0-9]+)',output,re.I)[0]})
             if re.findall('txload +([0-9]+\/[0-9]+)',output,re.I):
                 dict[intf_name].update({'txload':re.findall('txload +([0-9]+\/[0-9]+)',output,re.I)[0]})
             if re.findall('rxload +([0-9]+\/[0-9]+)',output,re.I):
                 dict[intf_name].update({'rxload':re.findall('rxload +([0-9]+\/[0-9]+)',output,re.I)[0]})
             if re.findall('Port +mode +is +([a-z]+)',output,re.I):
                 dict[intf_name].update({'mode':re.findall('Port +mode +is +([a-z]+)',output,re.I)[0]})
             if re.findall('(auto-speed+|[0-9]+ (?:mb|gb)\/s)',output,re.I):
                 dict[intf_name].update({'speed':re.findall('(auto-speed+|[0-9]+ (?:mb|gb)\/s)',output,re.I)[0]})
             negotiation= re.findall('Auto-Negotiation is turned (on|off)',output,re.I)
             if (negotiation):
                 dict[intf_name].update({'negotiation':negotiation[0]})

             if re.findall('Input flow-control is (on|off)',output,re.I):
                 dict[intf_name].update({'in_flow_control':re.findall('Input flow-control is (on|off)',output,re.I)[0]})
             if re.findall('Output flow-control is (on|off)',output,re.I):
                 dict[intf_name].update({'out_flow_control':re.findall('Output flow-control is (on|off)',output,re.I)[0]})
             if re.findall('Switchport monitor is (on|off)',output,re.I):
                 dict[intf_name].update({'monitor':re.findall('Switchport monitor is (on|off)',output,re.I)[0]})
             if re.findall('([0-9]+) interface resets',output,re.I):
                 dict[intf_name].update({'resets':re.findall('([0-9]+) interface resets',output,re.I)[0]})
             #get 5 minutes input rate in bps and pps
             if re.findall('input rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I):
                 dict[intf_name].update({'in_bps':re.findall('input rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I)[0][0]})
             if re.findall('input rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I):
                 dict[intf_name].update({'in_pps':re.findall('input rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I)[0][1]})
             #get 5 minutes output rate in bps and pps
             if re.findall('output rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I):
                 dict[intf_name].update({'out_bps':re.findall('output rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I)[0][0]})
             if re.findall('output rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I):
                 dict[intf_name].update({'out_pps':re.findall('output rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I)[0][1]})

             count='[0-9]+'
             space='[\t\n\r ]+'

             if re.search('mgmt',intf_name):
                 print ("inside mgmt \n")
                 pat = 'RX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) input packets +({0}) bytes'.format(count,space)
                 if re.findall(pat, output, re.I ):
                     print ("inside search \n")
                     rx_counter=re.findall(pat,output,re.I)
                     rx_counter[0]=('rx',)+rx_counter[0]
                     tmp=convertListToDict(rx_counter,['rx','unicast_packets','multicast_packets','broadcast_packets','input_packets','input_bytes'],'rx')
                     dict[intf_name].update(tmp)
                 pat='TX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) output packets +({0}) bytes'.format(count,space)
                 if re.findall(pat, output, re.I ):
                     print ("inside search Tx\n")
                     tx_counter=re.findall(pat,output,re.I)
                     tx_counter[0]=('tx',)+tx_counter[0]
                     tmp=convertListToDict(tx_counter,['tx','unicast_packets','multicast_packets','broadcast_packets','output_packets','output_bytes'],'tx')
                     dict[intf_name].update(tmp)

             if re.search('Nve',intf_name):
                 print ("inside nve \n")
                 pat = 'RX{1}({0}) unicast packets\s+({0}) multicast packets'.format(count,space)
                 if re.findall(pat, output, re.I ):
                     print ("inside search \n")
                     rx_counter=re.findall(pat,output,re.I)
                     rx_counter[0]=('rx',)+rx_counter[0]
                     tmp=convertListToDict(rx_counter,['rx','unicast_packets','multicast_packets'],'rx')
                     dict[intf_name].update(tmp)
                 pat='TX{1}({0}) unicast packets\s+({0}) multicast packets'.format(count,space)
                 if re.findall(pat, output, re.I ):
                     print ("inside search Tx\n")
                     tx_counter=re.findall(pat,output,re.I)
                     tx_counter[0]=('tx',)+tx_counter[0]
                     tmp=convertListToDict(tx_counter,['tx','unicast_packets','multicast_packets'],'tx')
                     dict[intf_name].update(tmp)


             #get RX counters
             pattern='RX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) input packets +({0}) bytes{1}({0}) jumbo packets +({0}) runts +({0}) giants +({0}) CRC +({0}) no buffer{1}({0}) input error +({0}) short frame +({0}) overrun +({0}) underrun +({0}) ignored{1}({0}) watchdog +({0}) bad etype drop +({0}) bad proto drop +({0}) if down drop{1}({0}) input with dribble +({0}) input discard{1}({0}) Rx pause'.format(count,space)
             if re.findall(pattern, output, re.I ):
                 rx_counter=re.findall(pattern,output,re.I)
                 rx_counter[0]=('rx',)+rx_counter[0]
                 tmp=convertListToDict(rx_counter,['rx','unicast_packets','multicast_packets','broadcast_packets','input_packets','input_bytes','jumbo_packets', 'runts','giants','crc','no_buffer','input_error','short_frame','overrun','underrun','ignored','watchdog','bad_etype_drop','bad_proto_drop','if_down_drop','input_with_dribble','input_discard','pause'],'rx')
                 dict[intf_name].update(tmp)

             # Handle Rx with Storm suppression byte counters ..
             pattern='RX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) input packets +({0}) bytes{1}({0}) jumbo packets +({0}) storm suppression bytes{1}({0}) runts +({0}) giants +({0}) CRC +({0}) no buffer{1}({0}) input error +({0}) short frame +({0}) overrun +({0}) underrun +({0}) ignored{1}({0}) watchdog +({0}) bad etype drop +({0}) bad proto drop +({0}) if down drop{1}({0}) input with dribble +({0}) input discard{1}({0}) Rx pause'.format(count,space)
             if re.findall(pattern, output, re.I ):
                 rx_counter=re.findall(pattern,output,re.I)
                 rx_counter[0]=('rx',)+rx_counter[0]
                 tmp=convertListToDict(rx_counter,['rx','unicast_packets','multicast_packets','broadcast_packets','input_packets','input_bytes','jumbo_packets','storm_suppression_bytes','runts','giants','crc','no_buffer','input_error','short_frame','overrun','underrun','ignored','watchdog','bad_etype_drop','bad_proto_drop','if_down_drop','input_with_dribble','input_discard','pause'],'rx')
                 dict[intf_name].update(tmp)

             # Handle Rx with Storm suppression packet counters ..
             pattern='RX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) input packets +({0}) bytes{1}({0}) jumbo packets +({0}) storm suppression packets{1}({0}) runts +({0}) giants +({0}) CRC +({0}) no buffer{1}({0}) input error +({0}) short frame +({0}) overrun +({0}) underrun +({0}) ignored{1}({0}) watchdog +({0}) bad etype drop +({0}) bad proto drop +({0}) if down drop{1}({0}) input with dribble +({0}) input discard{1}({0}) Rx pause'.format(count,space)
             if re.findall(pattern, output, re.I ):
                 rx_counter=re.findall(pattern,output,re.I)
                 rx_counter[0]=('rx',)+rx_counter[0]
                 tmp=convertListToDict(rx_counter,['rx','unicast_packets','multicast_packets','broadcast_packets','input_packets','input_bytes','jumbo_packets','storm_suppression_packets','runts','giants','crc','no_buffer','input_error','short_frame','overrun','underrun','ignored','watchdog','bad_etype_drop','bad_proto_drop','if_down_drop','input_with_dribble','input_discard','pause'],'rx')
                 dict[intf_name].update(tmp)


             #get TX counters
             pattern='TX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) output packets +({0}) bytes{1}({0}) jumbo packets{1}({0}) output erro[rs]+ +({0}) collision +({0}) deferred +({0}) late collision{1}({0}) lost carrier +({0}) no carrier +({0}) babble +({0}) output discard{1}({0}) Tx pause'.format(count,space)
             if re.findall(pattern,output,re.I):
                 tx_counter=re.findall(pattern,output,re.I)
                 tx_counter[0]=('tx',)+tx_counter[0]
                 tmp=convertListToDict(tx_counter,['tx','unicast_packets','multicast_packets','broadcast_packets','output_packets','output_bytes','jumbo_packets','output_error','collision','deferred','late_collision','lost_carrier','no_carrier','babble','output_discard','pause'],'tx')
                 dict[intf_name].update(tmp)
     return dict
 

              

def getInterfaceStatisticsDict( hdl, log, interface):

    #Returns dictionary of interface statistics with keys of "status","rxload","tx" etc.
    #e.g.
    #{'status': 'down', 'rxload': '1/255', \
    #'tx': {'pause': '0', 'output_bytes': '128251733', 'broadcast_packets': '0', 'deferred': '0', 'babble': '0', 'output_error': '0', 'no_carrier': '0', 'collision': '0', 'output_packets': '2000745', 'output_discard': '0', 'lost_carrier': '0', 'unicast_packets': '2000000', 'multicast_packets': '745', 'jumbo_packets': '0', 'late_collision': '0'},\
    # 'bia': '64a0.e73f.6ee3', 'hardware': '1000/10000 Ethernet', 'bandwidth': '10000000', 'reliability': '255/255', 'in_flow_control': 'off', 'in_bps': '0', 'resets': '1', 'speed': '1000 Mb/s', 'monitor': 'off', 'name': 'Ethernet3/24', 'txload': '1/255',\
    # 'rx': {'ignored': '0', 'storm_suppression_packets': '0', 'broadcast_packets': '0', 'bad_etype_drop': '0', 'runts': '0', 'watchdog': '0', 'input_discard': '0', 'input_packets': '2000000', 'underrun': '0', 'if_down_drop': '0', 'input_with_dribble': '0', 'unicast_packets': '2000000', 'input_error': '0', 'multicast_packets': '0', 'short_frame': '0', 'giants': '0', 'input_bytes': '128000000', 'pause': '0', 'bad_proto_drop': '0', 'overrun': '0', 'crc': '0', 'no_buffer': '0', 'jumbo_packets': '0'},\
    # 'mac': '64a0.e73f.6ee3', 'negotiation': 'on', 'mtu': '1500', 'delay': '10', 'out_flow_control': 'off', 'in_pps': '0', 'eee': 'Disabled', 'out_bps': '0', 'out_pps': '0', 'mode': 'access'}

    msg='Fetch statistics on interface {0} on switch {1}'.format(interface,hdl)
    log.info(msg)
    sw_cmd='show interface {0}'.format(interface)
    output=hdl.execute(sw_cmd)
    int=re.findall('({0}) +is (up|down)'.format(rex.INTERFACE_NAME),output,re.I)
    if (len(int)==0):
        return int
    dict={'name':int[0][0]}
    dict.update({'status':int[0][1]})
    hardware=re.findall('Hardware: +([0-9\/]+ [A-Za-z]+), +address: ({0}) +\(bia +({0})\)'.format(rex.MACADDR),output,re.I)
    hardware_no_bia=re.findall('Hardware is ([0-9A-Za-z]+), address is\s+({0})'.format(rex.MACADDR),output,re.I)
    if (hardware):
        dict.update({'hardware':hardware[0][0]})
        dict.update({'mac':hardware[0][1]})
        dict.update({'bia':hardware[0][2]})
    elif (hardware_no_bia):
        dict.update({'hardware':hardware_no_bia[0][0]})
        dict.update({'mac':hardware_no_bia[0][1]})

    if re.findall('MTU +([0-9]+) +bytes',output, re.I):
        dict.update({'mtu':re.findall('MTU +([0-9]+) +bytes',output, re.I)[0]})
    if re.findall('BW +([0-9]+) +kbit',output,re.I):
        dict.update({'bandwidth':re.findall('BW +([0-9]+) +kbit',output,re.I)[0]})
    if re.findall('DLY +([0-9]+) +usec',output,re.I):
        dict.update({'delay':re.findall('DLY +([0-9]+) +usec',output,re.I)[0]})
    if re.findall('reliability +([0-9]+\/[0-9]+)',output,re.I):
        dict.update({'reliability':re.findall('reliability +([0-9]+\/[0-9]+)',output,re.I)[0]})
    if re.findall('txload +([0-9]+\/[0-9]+)',output,re.I):
        dict.update({'txload':re.findall('txload +([0-9]+\/[0-9]+)',output,re.I)[0]})
    if re.findall('rxload +([0-9]+\/[0-9]+)',output,re.I):
        dict.update({'rxload':re.findall('rxload +([0-9]+\/[0-9]+)',output,re.I)[0]})
    if re.findall('Port +mode +is +([a-z]+)',output,re.I):
        dict.update({'mode':re.findall('Port +mode +is +([a-z]+)',output,re.I)[0]})
    if re.findall('(auto-speed+|[0-9]+ (?:mb|gb)\/s)',output,re.I):
        dict.update({'speed':re.findall('(auto-speed+|[0-9]+ (?:mb|gb)\/s)',output,re.I)[0]})
    negotiation= re.findall('Auto-Negotiation is turned (on|off)',output,re.I)
    if (negotiation):
        dict.update({'negotiation':negotiation[0]})

    if re.findall('Input flow-control is (on|off)',output,re.I):
        dict.update({'in_flow_control':re.findall('Input flow-control is (on|off)',output,re.I)[0]})
    if re.findall('Output flow-control is (on|off)',output,re.I):
        dict.update({'out_flow_control':re.findall('Output flow-control is (on|off)',output,re.I)[0]})
    if re.findall('Switchport monitor is (on|off)',output,re.I):
        dict.update({'monitor':re.findall('Switchport monitor is (on|off)',output,re.I)[0]})
    #may not always be there
    #dict.update({'eee':re.findall('EEE \(efficient-ethernet\) : (disabled|enabled)',output,re.I)[0]})
    if re.findall('([0-9]+) interface resets',output,re.I):
        dict.update({'resets':re.findall('([0-9]+) interface resets',output,re.I)[0]})
    #get 5 minutes input rate in bps and pps
    if re.findall('input rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I):
        dict.update({'in_bps':re.findall('input rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I)[0][0]})
    if re.findall('input rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I):
        dict.update({'in_pps':re.findall('input rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I)[0][1]})
    #get 5 minutes output rate in bps and pps
    if re.findall('output rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I):
        dict.update({'out_bps':re.findall('output rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I)[0][0]})
    if re.findall('output rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I):
        dict.update({'out_pps':re.findall('output rate ({0}) [KMG]?bps, ({0}) [KMG]?pps'.format(rex.DECIMAL_NUM),output,re.I)[0][1]})

    count='[0-9]+'
    space='[\t\n\r ]+'
    #get RX counters
    if (hdl.device_type == "EOR" or hdl.device_type == "sTOR"):
        pattern='RX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) input packets +({0}) bytes{1}({0}) jumbo packets +({0}) runts +({0}) giants +({0}) CRC +({0}) no buffer{1}({0}) input error +({0}) short frame +({0}) overrun +({0}) underrun +({0}) ignored{1}({0}) watchdog +({0}) bad etype drop +({0}) bad proto drop +({0}) if down drop{1}({0}) input with dribble +({0}) input discard{1}({0}) Rx pause'.format(count,space)
    else:
        pattern='RX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) input packets +({0}) bytes{1}({0}) jumbo packets +({0}) storm suppression packets{1}({0}) runts +({0}) giants +({0}) CRC +({0}) no buffer{1}({0}) input error +({0}) short frame +({0}) overrun +({0}) underrun +({0}) ignored{1}({0}) watchdog +({0}) bad etype drop +({0}) bad proto drop +({0}) if down drop{1}({0}) input with dribble +({0}) input discard{1}({0}) Rx pause'.format(count,space)

    if re.findall(pattern, output, re.I ):
        rx_counter=re.findall(pattern,output,re.I)
        rx_counter[0]=('rx',)+rx_counter[0]
        if (hdl.device_type == "EOR" or hdl.device_type == "sTOR"):
            tmp=convertListToDict(rx_counter,['rx','unicast_packets','multicast_packets','broadcast_packets','input_packets','input_bytes','jumbo_packets','runts','giants','crc','no_buffer','input_error','short_frame','overrun','underrun','ignored','watchdog','bad_etype_drop','bad_proto_drop','if_down_drop','input_with_dribble','input_discard','pause'],'rx')
        else:
            tmp=convertListToDict(rx_counter,['rx','unicast_packets','multicast_packets','broadcast_packets','input_packets','input_bytes','jumbo_packets','storm_suppression_packets','runts','giants','crc','no_buffer','input_error','short_frame','overrun','underrun','ignored','watchdog','bad_etype_drop','bad_proto_drop','if_down_drop','input_with_dribble','input_discard','pause'],'rx')
        dict.update(tmp)
    #get TX counters
    pattern='TX{1}({0}) unicast packets +({0}) multicast packets +({0}) broadcast packets{1}({0}) output packets +({0}) bytes{1}({0}) jumbo packets{1}({0}) output error +({0}) collision +({0}) deferred +({0}) late collision{1}({0}) lost carrier +({0}) no carrier +({0}) babble +({0}) output discard{1}({0}) Tx pause'.format(count,space)
    if re.findall(pattern,output,re.I):
        tx_counter=re.findall(pattern,output,re.I)
        tx_counter[0]=('tx',)+tx_counter[0]
        tmp=convertListToDict(tx_counter,['tx','unicast_packets','multicast_packets','broadcast_packets','output_packets','output_bytes','jumbo_packets','output_error','collision','deferred','late_collision','lost_carrier','no_carrier','babble','output_discard','pause'],'tx')
        dict.update(tmp)
    return dict
 


#======================================================================================#
# getVpcDict - Method to get Vpc dictionary 
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
# optional args
# vpc - vpc id to get data of only one vpc 
#======================================================================================#
def getVpcDict(hdl,log,*args):
    arggrammar={}
    arggrammar['vpc']='-type int'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    sw_cmd="show vpc"

    if ns.vpc:
          sw_cmd=sw_cmd + " " + str(ns.vpc)

    output=hdl.execute(sw_cmd)
    pat='([0-9]+)[ \t]+(Po[0-9]+)[ \t]+([a-z]+.*?)[ \t]+([a-z]+)[ \t]+([a-z]+)[ \t]+([^ ]+)'
    vpc_list=re.findall( pat, output, flags=re.M)
    vpc_dict=convertListToDict(vpc_list,['id','Port','Status','Consistency','Reason','Active_vlans'],['id'])

    if len(vpc_list)==0:
         msg='No vpcs found on {0}'.format(hdl.switchName)
         log.info(msg)
    return vpc_dict

##############################################################################

def getShowVpcDict(hdl,log):

    """
    This command parses <show vpc> output and returns various configuration in Dict format.
    There is another get method which deals with the same command but that returns only 
    vPC info (getVpcDict)

    """
    ShowVpcDict = {}
    log.info ('get show vpc info on {0}'.format(hdl.switchName))

    cmd_out=hdl.execute('show vpc')
    match = re.search('vPC domain id\s+:\s+({0})'.format(rex.NUM),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['vPC_domain_id'] = match.group(1)

    match = re.search('Peer status\s+:\s+peer adjacency formed ok',cmd_out,flags=re.I)
    match2 = re.search('peer link not configured',cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Peer_status'] = 'peer_adjacency_formed_ok'
    elif match2:
        ShowVpcDict['Peer_status'] = 'peer_link_not_configured'
    else:
        ShowVpcDict['Peer_status'] = 'not_ok'

    match = re.search('vPC keep-alive status\s+:\s+peer is alive',cmd_out,flags=re.I)
    if match:
        ShowVpcDict['vPC_keep-alive_status'] = 'peer_is_alive'
    else:
        ShowVpcDict['vPC_keep-alive_status'] = 'not_alive'

    match = re.search('Configuration consistency status\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Configuration_consistency_status'] = match.group(1)

    match = re.search('Per-vlan consistency status\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Per-vlan_consistency_status'] = match.group(1)
    match = re.search('Type-2 consistency status\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Type-2_consistency_status'] = match.group(1)

    match = re.search('vPC role\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['vPC_role'] =  match.group(1)

    match = re.search('vPC role\s+:\s+{0},\s+operational\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['vPC_role'] =  match.group(1)

    match = re.search('Number of vPCs configured\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Number_of_vPCs_configured'] = match.group(1)

    match = re.search('Peer Gateway\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Peer_Gateway'] = match.group(1)

    match = re.search('Dual-active excluded VLANs\s+:\s+([0-9\-]+)',cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Dual-active_excluded_VLANs'] = match.group(1)

    match = re.search('Graceful Consistency Check\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Graceful_Consistency_Check'] = match.group(1)

    match = re.search('Auto-recovery status\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Auto-recovery_status'] = match.group(1)

    match = re.search('Operational Layer3 Peer-router\s+:\s+({0})'.format(rex.ALPHA),cmd_out,flags=re.I)
    if match:
       ShowVpcDict['Layer3_Peer-router'] = match.group(1)
         
    #match = re.search('[0-9]+\s+(Po[0-9]+)\s+([a-z]+)\s+([0-9\-]+)',cmd_out,flags=re.I)
    match = re.search('[0-9]+\s+(Po[0-9]+)\s+([a-z]+)\s+({0})'.format(rex.VLAN_RANGE),cmd_out,flags=re.I)
    if match:
        ShowVpcDict['Peer-link_Port'] = match.group(1)
        ShowVpcDict['Peer-link_Status'] = match.group(2)
        ShowVpcDict['Peer-link_Active_vlans'] = match.group(3)
    return ShowVpcDict



#======================================================================================#
# getVpcList - Method to get list of all Vpcs configured 
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
# -pc-list: will give all vPC Po list instead of vPC id list
#======================================================================================#
def getVpcList(hdl,log,*args):
  
    arggrammar={}
    arggrammar['pc_list'] = '-type bool -default False'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    pc_list_flag=parse_output.pc_list
    vpc_dict=getVpcDict(hdl,log)
    if pc_list_flag:
        pc_list=[]
        for key in vpc_dict.keys():
            pc_list.append(vpc_dict[key]['Port'])
        return sorted(pc_list)
    else:
        vpc_list=[]
        vpc_list=sorted(vpc_dict.keys())
        msg="List of Vpcs - {0}".format(vpc_list)
        log.info(msg)
        return vpc_list


#======================================================================================#
# getVpcUpList - Method to get list of Vpcs that are in up state
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#======================================================================================#
def getVpcUpList(hdl,log,*args):

    arggrammar={}
    arggrammar['pc_list'] = '-type bool -default False'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    pc_list_flag=parse_output.pc_list
    vpc_dict=getVpcDict(hdl,log)
    if pc_list_flag:
        pc_up_list=[]
        for vpc in vpc_dict.keys():
            if vpc_dict[str(vpc)]['Status']=='up':
                pc_up_list.append(vpc_dict[vpc]['Port'])
        return sorted(pc_up_list)
    else:
        vpc_up_list=[]
        for vpc in vpc_dict.keys():
            if vpc_dict[str(vpc)]['Status']=='up':
                vpc_up_list.append(vpc)
        return sorted(vpc_up_list)



def getTacacsServerList(hdl,log):

    # Returns TACACS server List
    showoutput=hdl.execute("show tacacs-server") 
    pattern="("+rex.IPv4_ADDR+")"
    tacacsserverlist=re.findall(pattern,showoutput,flags=re.I|re.M)
    log.info("Radius server dict : " + str(tacacsserverlist))
    return tacacsserverlist

def getRadiusServerList(hdl,log):

    # Returns Radius server List
    showoutput=hdl.execute("show radius-server")
    pattern="("+rex.IPv4_ADDR+")"
    radiusserverlist=re.findall(pattern,showoutput,flags=re.I|re.M)
    log.info("Radius server dict : " + str(radiusserverlist))
    return radiusserverlist

def getInventoryDict(hdl,log,*args):

    # Returns dictionary with name as first level key
    #  descr pid vid sn as second level keys
   
    arggrammar={}
    arggrammar['chassis'] = '-type bool'
    arggrammar['clock'] = '-type bool' 
    arggrammar['fans'] = '-type bool'
    arggrammar['module'] = '-type bool' 
    arggrammar['power_supply'] = '-type bool'
    arggrammar['xbar'] = '-type bool' 

    cmd = "show inventory " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    showoutput=hdl.execute(cmd)
    namelist=re.findall("NAME:[ \t]*\"([^\"]+)",showoutput,flags=re.I|re.M)
    descrlist=re.findall("DESCR:[ \t]*\"([^\"]+)",showoutput,flags=re.I|re.M)
    pidlist=re.findall("PID:[ \t]+([^ \t]+)",showoutput,flags=re.I|re.M)
    vidlist=re.findall("VID:[ \t]*([ANV0-9\/]+)",showoutput,flags=re.I|re.M)
    snlist=re.findall("SN:[ \t]*([0-9A-Za-z]+)",showoutput,flags=re.I|re.M)

    returndict = {}
    if len(namelist) == len(descrlist) and len(descrlist) == len(pidlist) and len(pidlist) == len(vidlist) and len(vidlist) == len(snlist):
       for name in namelist:
           returndict[name]={}
           index=namelist.index(name)
           returndict[name]['descr'] = descrlist[index] 
           returndict[name]['pid'] = pidlist[index] 
           returndict[name]['vid'] = vidlist[index] 
           returndict[name]['sn'] = snlist[index] 
    else:
       log.error("No.of names: {0} No.of descriptions: {1} No. of pids: {2} No of vids: {3} No of SNs: {4}".format(len(namelist),len(descrlist),len(pidlist),len(vidlist),len(snlist)))
       log.error("names " + str(namelist))
       log.error("descr " + str(descrlist))
       log.error("pid " + str(pidlist))
       log.error("vid " + str(vidlist))
       log.error("sn " + str(snlist))

    log.debug("Inventory Dict " + str(returndict)) 
    return returndict 

def getMacAddressAgingtimeDict(hdl,log, *args):

    # Returns a dictionary with vlan as key & agingtime as value 
    arggrammar={} 
    arggrammar['vlan']='-type int'

    cmd = "show mac address-table aging-time " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    showoutput=hdl.execute(cmd)
    agingtimelist=re.findall("("+rex.NUM+")[ \t]+("+rex.NUM+")",showoutput,flags=re.I|re.M)
    agingtimedict=convertListToDict(agingtimelist,['vlan','agingtime'],['vlan'])
    log.debug("Aging time dictionary is : " + str(agingtimedict))
    return agingtimedict

def getVlanDict(hdl,log,*args):

    # Returns a dictionary with vlan as key & members as value

    arggrammar={}
    arggrammar['vlans']='-type str'
    optionns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if 'vlans' in optionns.KEYS:
        cmd = "show vlan id " + optionns.vlans 
    else:
        cmd = "show vlan " 
    showoutput=hdl.execute(cmd)

    vlanmemberlist=re.findall("("+rex.NUM+")[ \t]+("+rex.ALPHANUM+")[ \t]+("+rex.VLAN_STATUS+")[ \t]+(.*)",getUnwrappedBuffer(showoutput,", "),flags=re.I|re.M)
    vlanmemberdict=convertListToDict(vlanmemberlist,['VLAN','Name','Status','Ports'],['VLAN'])
    log.debug("VLAN brief dictionary is " + str(vlanmemberdict))
    return vlanmemberdict

def getInterfaceSwitchportDict(hdl,log,*args):
    ''' returns dictionary of interface switchport attributes as keys.
        sample usage : getInterfaceSwitchportDict(hdl,log, '-interface eth1/1')
        sample return dict :
        {'Administrative private-vlan primary mapping': 'none', 
         'Administrative private-vlan trunk normal VLANs': 'none', 
         'Voice VLAN': 'none', 'Unknown multicast blocked': 'disabled', 
         'Switchport': 'Enabled', 'Administrative private-vlan primary host-association': 'none', 
         'Access Mode VLAN': '993', 'Administrative private-vlan secondary mapping': 'none', 
         'Administrative private-vlan trunk encapsulation': 'dot1q', 
         'Administrative private-vlan trunk native VLAN': 'none', 'Switchport Monitor': 'Not', 
         'Trunking Native Mode VLAN': '201', 'Extended Trust State ': 'not', 
         'Unknown unicast blocked': 'disabled', 
         'Administrative private-vlan secondary host-association': 'none', 
         'Operational private-vlan': 'none', 'Administrative private-vlan trunk private VLANs': 'none', 
         'Operational Mode': 'access', 'Trunking VLANs Allowed': '1-201'} '''

    arggrammar={}
    arggrammar['interface']='-type str -format {0} -required True'.format(rex.INTERFACE_NAME)
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    interface=ns.interface
    msg='Fetch switchport details for input interface {0} on switch {1}'.format(interface,hdl.switchName)
    log.info(msg)
    sw_cmd='show interface {0} switchport'.format(interface)
    output=hdl.execute(sw_cmd)
    int=re.findall('Name: ({0})'.format(rex.INTERFACE_NAME),output,re.I)
    if (len(int)==0):
        return {}
    switchport_dict={}
    for line in output.split("\n"):
        parsed_list= re.findall("\s+([^:]+):\s+([^:\s]+)",line)
        if len(parsed_list):
            switchport_dict[parsed_list[0][0]]=parsed_list[0][1]
    return switchport_dict

def getDeviceType(hdl,log):

    cmd = "show version"
    showoutput=hdl.execute(cmd)
    typelist=re.findall("(Nexus[0-9]+) ",showoutput,flags=re.I|re.M)
    if len(typelist) > 0:
       return typelist[0]
    else:
       return ""

def getDeviceSubtype(hdl,log):

    cmd = "show version"
    showoutput=hdl.execute(cmd)
    typelist=re.findall("Nexus[0-9]+ ([A-Za-z0-9]+) ",showoutput,flags=re.I|re.M)
    if len(typelist) > 0:
       return typelist[0]
    else:
       return ""




def getShowSpanningTreeDict( hdl, log, *args ):

    """
    getShowSpanningTreeDict - returns the output of show spanning-tree in dictionary format
    Optional arguments are -vlan and -interface
    Usage: 
       getShowSpanningTreeDict( hdl, log )
       getShowSpanningTreeDict( hdl, log, '-vlan 2' )
       getShowSpanningTreeDict( hdl, log, '-interface Po1' )
       getShowSpanningTreeDict( hdl, log, '-vlan 2 -interface Po1' )

    The dictionary has vlan_id as the primary key and the following under vlan_id
      'root_flag' - Set to True of False
      'root_info' - Section of the Root ID info in dictionary format
      'bridge_info' - Section of the Bridge ID info in dictionary format
      'interface_info' - Section of the STP interfaces with Role, State, Cost etc. in dictionary format
     
    """

    # Parse Arguments ..
    arggrammar={}
    arggrammar['vlan']='-type int'
    arggrammar['interface']='-type str'
  
    show_stp_dict=collections.OrderedDict()
 
    ns=parserutils_lib.argsToCommandOptions( args, arggrammar, log )


    # Define the Regexp Patterns to Parse ..

    root_params_pat_non_root='\s+Root ID\s+Priority\s+([0-9]+)\r\n\s+Address\s+({0})\r\n\s+Cost\s+([0-9]+)\r\nPort\s+([0-9]+)\s+\(([a-zA-Z0-9\-]+)\)\r\n\s+Hello Time\s+([0-9]+)\s+sec\s+Max\s+Age\s+([0-9]+)\s+sec\s+Forward\s+Delay\s+([0-9]+)\s+sec\r\n'.format(rex.MACADDR)
    root_params_pat_root='\s+Root ID\s+Priority\s+([0-9]+)\r\n\s+Address\s+({0})\r\n\s+This bridge is the root\r\n\s+Hello Time\s+([0-9]+)\s+sec\s+Max\s+Age\s+([0-9]+)\s+sec\s+Forward\s+Delay\s+([0-9]+)\s+sec\r\n'.format(rex.MACADDR)
    bridge_params_pat='\s+Bridge ID\s+Priority\s+([0-9]+)\s+\(priority\s+([0-9]+)\s+sys-id-ext ([0-9]+)\)\r\n\s+Address\s+({0})\r\n\s+Hello\s+Time\s+([0-9]+)\s+sec\s+Max\s+Age\s+([0-9+)\s+sec\s+Forward Delay\s+([0-9]+) sec\r\n'.format(rex.MACADDR)
    #interface_params_pat='-------\r\n({0})\s+([a-zA-Z]+)\s+([A-Z]+)\s+([0-9]+)\s+([0-9]+).([0-9]+)\s+([\(\)a-zA-Z0-9\s]+)\r'.format(rex.INTERFACE_NAME)
    interface_params_pat='({0})\s+([a-zA-Z]+)\s+([A-Z]+)[\*\s]+([0-9]+)\s+([0-9]+).([0-9]+)\s+'.format(rex.INTERFACE_NAME)


    # Build the command to be executed based on the arguments passed ..
    cmd = 'show spanning-tree '

    if ns.vlan is not None:
        cmd = cmd + 'vlan {0}'.format(ns.vlan)

    if ns.interface is not None:
        cmd = cmd + 'interface {0}'.format(ns.interface)


    show_stp=hdl.execute(cmd)

    # Split the output of STP based on VLAN
    show_stp_vlan_split=show_stp.split('VLAN')


    # Iterate over every VLAN block and build the show_stp_dict
    for stp_vlan in show_stp_vlan_split:

      if re.search( '^([0-9]+)', stp_vlan ):

         match=re.search( '^([0-9]+)\r\n\s+Spanning tree enabled protocol ([a-z]+)', stp_vlan, re.I )
         vlan_id = int(match.group(1))
         stp_mode = match.group(2)
         show_stp_dict[vlan_id]={}
         show_stp_dict[vlan_id]['stp_mode']=stp_mode
         

         if re.search( root_params_pat_root, stp_vlan, re.I ):
             root_info=re.findall( root_params_pat_root, stp_vlan, re.I )
             show_stp_dict[vlan_id]['root_info']=convertListToDict( root_info, ['Priority','Address', \
                 'Hello Time','Max Age','Forward Delay'], ['Priority','Address'])
             show_stp_dict[vlan_id]['root']=True
         else:
             root_info=re.findall( root_params_pat_non_root, stp_vlan, re.I )
             show_stp_dict[vlan_id]['root_info']=convertListToDict( root_info, ['Priority','Address','Cost', \
                 'Port','Hello Time','Max Age','Forward Delay'], ['Priority','Address','Cost', 'Port'])
             show_stp_dict[vlan_id]['root']=False

         bridge_info=re.findall( bridge_params_pat, stp_vlan, re.I )
         show_stp_dict[vlan_id]['bridge_info']=convertListToDict( root_info, ['Priority','Address', \
                'Hello Time','Max Age','Forward Delay'], ['Priority','Address'])

         intf_info=re.findall( interface_params_pat, stp_vlan, re.I )
         show_stp_dict[vlan_id]['interface_info']=convertListToDict( intf_info, [ 'Interface', 'Role', 'Status', \
                'Cost', 'Prio', 'Nbr' ] , [ 'Interface' ] )

    print(' %%%%%%%%%% show_stp_dict %%%%%%%%%', show_stp_dict )
    log.info(' %%%%%%% show_stp_dict %%%%%%%% {0}'.format(show_stp_dict) )
    return show_stp_dict
    
         

    
def getSpanningTreePortStateDict(hdl,log,*args):

    # Returns a dict with 'vlan' as first level key and
    # 'role','cost','state','prio.nbr','type' as second level keys 

    arggrammar={}
    arggrammar['interface']='-required True'
    cmd = "show spanning-tree " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    showoutput=hdl.execute(cmd)
    stplist=re.findall("^VLAN0*([0-9]+)[ \t]+([^ \t]+)[ \t]+([A-Za-z]+)[ \t]+([0-9]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t\r\n]+",showoutput,flags=re.I|re.M)
    stpdict=convertListToDict(stplist,['vlan','role','state','cost','prio.nbr','type'],['vlan'])
    log.debug(" STP state is : " + str(stpdict))
    return stpdict

def getMSpanningTreePortStateDict(hdl,log,*args):

    # Returns a dict with 'mst_instance_id' as first level key and
    # 'role','cost','state','prio.nbr','type' as second level keys 

    arggrammar={}
    arggrammar['interface']='-required True'
    cmd = "show spanning-tree " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    showoutput=hdl.execute(cmd)
    stplist=re.findall("^MST0*([0-9]+)[ \t]+([^ \t]+)[ \t]+([A-Za-z]+)[ \t]+([0-9]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t\r\n]+",showoutput,flags=re.I|re.M)
    stpdict=convertListToDict(stplist,['mst','role','state','cost','prio.nbr','type'],['mst'])
    log.debug(" STP state is : " + str(stpdict))
    return stpdict

#======================================================================================#
# getSpanningTreeVlanPortStateDict - Method to get stp state details for a given vlan 
#                                    and interface using 'show spanning-tree vlan x 
#                                    interface y' output
#
# == Mandatory args ==
# -vlan <id>
# -interface <id>
#
# == Caller format example ==
# eor_utils.getSpanningTreeVlanPortStateDict(hdl,log,'-vlan 2 ','-interface eth1/1')
#
# == Return Dictionary ==
# Returns dict with keys : vlan, role, state, cost, pri.nbr, type
#
# == Return Dictionary sample ==
# ([('vlan', 'VLAN0002'), ('role', 'Desg'), ('state', 'FWD'), ('cost', '2'), 
#   ('prio.nbr', '128.129'), ('type', 'P2p')])
#======================================================================================#
def getSpanningTreeVlanPortStateDict(hdl,log,*args):
    arggrammar={}
    arggrammar['vlan']='-type int -required True'
    arggrammar['interface']='-type str -required True'
    cmd = "show spanning-tree " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    showoutput=hdl.execute(cmd)
    stplist=re.findall("^([^ \t]+)[ \s]+([^ \t]+)[ \s]+([A-Za-z]+)[ \s]+([0-9]+)[ \s]+\
    ([^ \t]+)[ \s]+([^ \t]+)[ \s\r\n]+",showoutput,flags=re.I|re.M)
    if stplist:
        # if vlan port state is found
        stpdict=convertListToDict(stplist,['vlan','role','state','cost','prio.nbr','type'])
        log.info(" STP state for " + \
        parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str") + " is : " + str(stpdict))
        return stpdict
    else:
        # if vlan port stp state is not found
        msg="STP state does not exist for this " + parserutils_lib.argsToCommandOptions\
        (args,arggrammar,log,"str") + " check for valid interface and vlan"
        log.info(msg)
        return ""

#======================================================================================#
# getSpanningTreeMode - Method to get running spanning tree mode on the switch
#
# == Return value sample ==
# returns a simple str 
# mst - when running mode is mst
# rapid-pvst - when running mode is rst
# null - when mode is not found in output or cli output fails
#======================================================================================#
def getSpanningTreeMode(hdl,log):
    msg='Fetch spanning tree mode running on the switch'
    log.info(msg)
    cmd="show spanning-tree summary | incl mode"
    output=hdl.execute(cmd)
    stpmode = re.search('Switch is in (.+)[ \t]+mode',output,re.I)
    if stpmode:
        return stpmode.group(1)
    else :
        msg='STP mode not found in output'
        log.info(msg)
        return ""  


#======================================================================================#
# getSpanningTreeBridgeAssuranceState - Method to get running spanning tree BA  on the switch
#
# == Return value sample ==
# returns a simple str
# enabled - when running state is enabled
# disabled - when runnning state is disabled
# null - when bridge assurance is not enabled  in output or cli output fails
#======================================================================================#

def getSpanningTreeBridgeAssuranceState(hdl,log):
    msg='Fetch spanning tree bridge assurance state running on the switch'
    log.info(msg)
    cmd="show spanning-tree summary totals | incl Assurance"
    output=hdl.execute(cmd)
    stpbridgeState = re.search('Bridge Assurance [ \t]+  is ([A-Za-z ]+)',output,re.I)
    log.info('STPBRIDGE STATE is {0}'.format(stpbridgeState))
    if stpbridgeState:
        return stpbridgeState.group(1)
    else :
        msg='STP Bridge Assurance is not found in output'
        log.info(msg)
        return ""


#======================================================================================#
# getSpanningTreeInconsistentPorts-  Method to return inconsistent port number
#
# == Return value sample ==
# returns a simple str
#  returns port-list  if there is any inconsistent port
# null - when there are no inconsistent port
#======================================================================================#

def getSpanningTreeInconsistentPorts(hdl,log):
    msg='Fetch spanning tree inconsistent ports '
    log.info(msg)
    cmd="show spanning-tree inconsistentports | incl  Eth"
    output=hdl.execute(cmd)
    log.info('OUTPUT IS : {0}'.format(output))
    log.info('getSpanningTreeInconsistentPorts - CHECK')
    lines = output.splitlines()
    port_list = []
    for line in lines:
        log.info('line is : {0}'.format(line))
        stpinconport  = re.search('[A-Za-z0-9]+[ \t]+([A-Za-z\/0-9]+)[ \t]+Root Inconsistent',line,re.I)
        log.info('Match output is {0}'.format(stpinconport))
        if stpinconport:
            port_list.append(stpinconport.group(1))
            log.info('PList is : {0}'.format(port_list))

    msg= 'Portlist, with inconsistentports are'
    log.info('Portlist, with inconsistentports are :  {0}'.format(port_list))

    return port_list


def getSpanningTreePeerSwitchState(hdl,log):
    """Return peer-switch operation state
    It returns one of following:
    not_enabled = feature not configured
    operational = feature enabled and operational
    non-operational = feature enabled and not operational
    """

    peer_switch_info = 'not_enabled'
    cmd_out =hdl.execute('show spanning-tree summary | inc "vPC peer-switch"')
    match  = re.search('vPC peer-switch\s+is enabled \(({0})\)'.format(rex.ALPHASPECIAL),cmd_out,re.I)
    if match:
        peer_switch_info = match.group(1)
    return peer_switch_info


#======================================================================================#
# getSpanningTreeStatesTotalDict - Method to get total count of various active stp port states 
#                              for all vlans
# Handles both rapid-pvst and mst modes
# == mandatory args ==
# hdl - switch handle object from icon
# log - harness/python logging object
#
# == Caller sample ==
# print eor_utils.getSpanningTreeStatesTotal(hdl,log)
#
# == Return dictionary keys ==
# returns a dictionary with single level keys for various stp port states and total counts
# keys - No of Vlans, Blocking, Listening, Learning, Forwarding, Total STP Active
#  
# == Return Dictionary sample ==
# [('Name', '25'), ('Blocking', '0'), ('Listening', '0'), ('Learning', '0'), ('Forwarding', '89'), ('Total STP Active', '89')]
#
#======================================================================================#
def getSpanningTreeStatesTotalDict(hdl, log):
    command="show spanning-tree summary totals "
    showoutput=hdl.execute(command)
    mode='(?:mst|vlans)'
    stptotalsummary=re.findall(\
         "^([0-9]+[ \t]+[A-Za-z]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+ ([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)".format(mode), showoutput, re.M | re.I)
    if not re.search("([0-9]+[ \t]+[A-Za-z]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+ ([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)",showoutput):
        log.info("REGEXP NOT MATCH")
        return
    else:
        stptotalsummary=re.findall("([0-9]+[ \t]+[A-Za-z]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+ ([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)".format(mode), showoutput, re.M | re.I) 
    stpstatesdict=convertListToDict(stptotalsummary,['Name','Blocking','Listening','Learning','Forwarding','STP_Active'])
    log.info("STP total states summary dictionary :" + str(stpstatesdict))
    return stpstatesdict

#======================================================================================#

# getSpanningTreeVlanStatesCountDict - Method to get count of various stp port-states on a given or all vlan
#
# == optional arg ==
#  vlan
#
# == Caller format example ==
#  eor_utils.getSpanningTreeVlanStatesCountDict(hdl,log)
#  eor_utils.getSpanningTreeVlanStatesCountDict(hdl,log,'-vlan 3')
#
# == Return Dictionary keys ==
# Vlan - first level key and various stp port states counts as second level key
# Blocking, Listening, Learning, Forwarding, STP Active - second level keys

# == Return Dictionary sample ==
#  1. Default with no args passed:
#  caller : print eor_utils.getSpanningTreeVlanStatesCountDict(hdl,log)
#  return 2 level keyed dict :
#  ([('1', OrderedDict([('Blocking', '0'), ('Listening', '0'), ('Learning', '0'), 
#                              ('Forwarding', '17'), ('STP Active', '17')])), 
#  ('2',   OrderedDict([('Blocking', '0'), ('Listening', '0'), ('Learning', '0'), 
#                              ('Forwarding', '4'), ('STP Active', '4')])), 
#  ('3', OrderedDict([('Blocking', '0'), ('Listening', '0'), ('Learning', '0'), 
#                            ('Forwarding', '4'), ('STP Active', '4')]))])
#  2. When valid vlan is passed:
#  caller : print eor_utils.getSpanningTreeVlanStatesCountDict(hdl,log,'-vlan 3')
#  return single level keyed dict : 
#  ([('Vlan', '3'), ('Blocking', '0'), ('Listening', '0'), ('Learning', '0'), 
#    ('Forwarding', '4'), ('STP Active', '4')])
#  3. When invalid/inactive/errorerd or nonexisting vlan is passed:
#  caller : print eor_utils.getSpanningTreeVlanStatesCountDict(hdl,log,'-vlan 100')
#  return null  with log.info 
#  "No STP states exist. Requested vlan 100 may not exist or inactive or errored"
#
#======================================================================================#

def getSpanningTreeVlanStatesCountDict(hdl,log,*args):
    arggrammar={}
    arggrammar['vlan']='-type str -format [0-9-, ]+'
    argnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    command = "show spanning-tree " + parseoutput + " summary"
    showoutput=hdl.execute(command)
    stpvlansummary=re.findall(\
         "VLAN0*([0-9]+)[ \s]+([0-9]+)[ \s]+([0-9]+)[ \s]+([0-9]+)[ \s]+([0-9]+)[ \s]+([0-9]+)[\s\t\r\n]+", showoutput, re.M | re.I)
    

    if stpvlansummary:
        # if valid match found
        if argnamespace.KEYS:
            # if vlan arg is passed then return dict with single level keys for all stp states summary 
            stpstatesdict=convertListToDict(stpvlansummary,['Vlan','Blocking','Listening','Learning','Forwarding','STP Active'],'Vlan')
        else:
            # if no args passed return dict with vlan as first level key, and all its states as second level keys 
            stpstatesdict=convertListToDict(stpvlansummary,['Vlan','Blocking','Listening','Learning','Forwarding','STP Active'],'Vlan')
        log.info("STP vlan port states summary dictionary :" + str(stpstatesdict))
        return stpstatesdict
    else:
        # if valid match not found
        log.info("No STP states exist. Requested vlan " + str(argnamespace.vlan) + " may not exist or inactive or errored")
        return ""

def getMSpanningTreeVlanStatesCountDict(hdl,log,*args):
    arggrammar={}
    argnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    command = "show spanning-tree summary"
    showoutput=hdl.execute(command)
    stpvlansummary=re.findall(\
         "MST0*([0-9]+)[ \s]+([0-9]+)[ \s]+([0-9]+)[ \s]+([0-9]+)[ \s]+([0-9]+)[ \s]+([0-9]+)[\s\t\r\n]+", showoutput, re.M | re.I)


    if stpvlansummary:
        # if valid match found
        if argnamespace.KEYS:
            # if vlan arg is passed then return dict with single level keys for all stp states summary 
            stpstatesdict=convertListToDict(stpvlansummary,['Vlan','Blocking','Listening','Learning','Forwarding','STP Active'],'Vlan')
        else:
            # if no args passed return dict with vlan as first level key, and all its states as second level keys 
            stpstatesdict=convertListToDict(stpvlansummary,['Vlan','Blocking','Listening','Learning','Forwarding','STP Active'],'Vlan')
        log.info("STP vlan port states summary dictionary :" + str(stpstatesdict))
        return stpstatesdict
    else:
        # if valid match not found
        log.info("No STP states exist. Requested vlan " + str(argnamespace.vlan) + " may not exist or inactive or errored")
        return ""

#======================================================================================#
# getVlanList - Method to get list of all vlans from show vlan output
#
# == Return value sample ==
# returns vlans in list format as fetched from show vlan ouput
# note : vlans status is ignored, all active/inactive/shut vlans are fetched 
# ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '25', '26', '31']
#======================================================================================#
def getVlanList( hdl,log ):
    msg='Fetch list of vlans configured on the switch'
    log.info(msg)
    cmd="show vlan"
    output=hdl.execute(cmd)
    vlanlist = re.findall('^([0-9]+)[ \t]+enet[ \t]+CE',output,re.M|re.I)
    return vlanlist

#======================================================================================#
# getActiveVlanList - Method to get list of all active vlans from show vlan output
#
# == Return value sample ==
# returns vlans in list format as fetched from show vlan ouput
# note : vlans status is ignored, all active/inactive/shut vlans are fetched 
# ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '25', '26', '31']
#======================================================================================#
def getActiveVlanList(hdl, log):
    cmd = 'show vlan brief'

    output = hdl.execute(cmd)
    lines = output.split('\n')
    pattern = '(^[0-9]+)[ \t]+\S+[ \t]+active[ \t]+\S+'

    vlan_list = []
    for line in lines:
        match = re.search(pattern, line)
        if match:
           vlan_list.append(match.group(1))
    return vlan_list 

#======================================================================================#
# getPvlanMembersDict- Method to get list of pvlan port-members and return a dict keyed by
#                      pri,scdry vlan pair using 'show vlan private-vlan' output
#
# == Caller format example ==
# eor_utils.getPvlanMemberDict(hdl,log)
#
# == Return Dictionary ==
# first level key - primary,secondary vlan pairs as first level key
# second level keys -Type, Ports as second level keys
#
# == Return Dictionary sample ==
#([(('690', '691'), OrderedDict([('Type', 'community'), ('Ports', 'Eth1/4, Eth1/8, Eth102/1/3')])), 
# (('690', '693'), OrderedDict([('Type', 'isolated'), ('Ports', 'Eth1/6, Eth1/7, Eth1/8, Eth102/1/1,
#                                                                Eth102/1/2')]))])
#
#======================================================================================#
def getPvlanMembersDict( hdl,log ):
    msg='Fetch list of pvlan port-members and return a dict keyed by pri,scdry vlan pair'
    log.info(msg)
    cmd="show vlan private-vlan "
    output=hdl.execute(cmd)
    # wrapping all port members to a single line
    output=getUnwrappedBuffer(output)
    pvlanmembers = \
    re.findall("^("+rex.NUM+")[ \s]+("+rex.NUM+")[ \s]+("+rex.ALPHA+")[ \s]+([ETHPO0-9/, ]+)",\
    output,re.M|re.I)
    if pvlanmembers:
        # if valid pvlan match found
        msg='Returning pvlan members dict '
        log.info(msg)
        pvlanmemdict= \
        convertListToDict(pvlanmembers,['Primary','Secondary','Type','Ports'],['Primary','Secondary'])
        return pvlanmemdict
    else:
        # if not valid match found or cli errored or pvlan not enabled
        msg='No valid Pvlan match found, check for pvlan feature and configs'
        log.info(msg)
        return ""

#======================================================================================#
# getPvlanTypeDict- Method to get list of private-vlans type and return a dict keyed by
#                   vlan using 'show vlan private-vlan type' output
#
# == Return Dictionary ==
# key:Vlan,value:Type
#
# == Return Dictionary sample ==
# ([('690', 'primary'), ('691', 'community'), ('692', 'community'), ('693', 'isolated')])
#======================================================================================#
def getPvlanTypeDict( hdl,log ):
    msg='Fetch list of private-vlans and return a dict with key:vlan, value:type'
    log.info(msg)
    cmd="show vlan private-vlan type"
    output=hdl.execute(cmd)
    pvlantype = re.findall("^("+rex.NUM+")[ \s]+("+rex.ALPHA+")",output,re.M|re.I)
    if pvlantype:
        # if valid pvlan match found
        # pvlantypedict=convertListToDict(pvlantype,['Vlan','Type'],'Vlan')
        # pvlantypedict=convertListToDict(pvlantype,['Vlan','Type'])
        # with just 2 columns in the output table, by default the first is 
        # used as key and the second column as value, so need not reference explicitly
        pvlantypedict=convertListToDict(pvlantype)
        msg='Pvlan and its type Dictionary ' + str(pvlantypedict)
        log.info(msg)
        return pvlantypedict
    else:
        # if not valid match found or cli errored or pvlan not enabled
        msg='No valid Pvlan match found, check for pvlan feature and configs'
        log.info(msg)
        return ""


#======================================================================================#
# getPortChannelLacpIndividualList - Method to get list of LACP po members in individual
#                                    state and not-aggregated, for a given po or all po's
# == optional arg ==
#  -pc_name po<id>
#
# == Caller format example ==
#  eor_utils.getPortChannelLacpIndividualList(hdl,log)
#  eor_utils.getPortChannelLacpIndividualList(hdl,log,'-pc_name po102')
#
# == Return list sample ==
# returns a list of LACP ports in individual state from 'show port-channel database' output
# ['Ethernet1/1', 'Ethernet1/2', 'Ethernet1/3', 'Ethernet1/4']
#
#======================================================================================#
def getPortChannelLacpIndividualList(hdl,log,*args):
    msg='Fetch list of not-aggregated LACP members in individual state'
    log.info(msg)
    arggrammar={}
    arggrammar['pc_name']='-type str'
    argnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if argnamespace.pc_name:
        command = "show port-channel database interface " + argnamespace.pc_name
    else:
        command = "show port-channel database "
    showoutput = hdl.execute(command)
    pat="("+rex.INTERFACE_NAME+").*active.*individual"
    lacpmemlist = re.findall(pat, showoutput, re.M | re.I)
    if len(lacpmemlist)==0:
        # if no LACP individual members, or po non-existent return null
        msg='No LACP members in Individual state, or check if po exists '
        log.info(msg)
        return ""
    else:
        # return list of PO members in LACP individual state
        msg='LACP members in individual state ' + str(lacpmemlist)
        log.info(msg)
        return lacpmemlist

def getSpanSessionsDict(hdl,log,*args):

    # Returns dict with span session id as first level key
    # and type,state,filtervlans,destionationports,sourceintfrx,sourceintftx,
    # sourceintfboth,sourcevlantx,sourcevlanrx,sourcevlanboth 
    # as second level keys

    returndict={}
    arggrammar={}
    arggrammar['session'] = '-type int'
    arggrammar['range'] = ''
    arggrammar['all'] = '-default all'
    arggrammar['mutualExclusive'] = [('session','range','all')]

    cmd = "show monitor session "
    cmdoptions = parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
    if len(cmdoptions.KEYS) > 0:
        if cmdoptions.session:
             cmd = cmd + cmdoptions.session
        elif cmdoptions.all: 
             cmd = cmd + "all"
        elif cmdoptions.range:
             cmd = cmd + " range " + cmdoptions.range

    showoutput=hdl.execute(cmd)
    #print showoutput
    outputlist=showoutput.split("session")

    if len(outputlist) <= 2:
        return returndict
   
    for index in range(2,len(outputlist)):
        outputstr=outputlist[index]
        thisrowlist=re.findall("^ ([0-9]+)",outputstr,flags=re.I|re.M)
        if len(thisrowlist) != 1:
           continue
        session=thisrowlist[0]
        returndict[session]={}
        typelist=re.findall("type[ \t]+:[ \t]+([a-zA-Z0-9]+)",outputstr,flags=re.I|re.M)
        if len(typelist) == 1:
            returndict[session]['type']=typelist[0]
        statelist=re.findall("state[ \t]+:[ \t]+([a-zA-Z0-9]+)",outputstr,flags=re.I|re.M)
        if len(statelist) == 1:
            returndict[session]['state']=statelist[0]
        filtervlanlist=re.findall("filter VLANs[ \t]+:[ \t]+([a-zA-Z0-9 .]+)",outputstr,flags=re.I|re.M)
        if len(filtervlanlist) == 1:
            returndict[session]['filtervlans']=filtervlanlist[0]
        destinationportlist=re.findall("destination ports[ \t]+:[ \t]+([a-zA-Z0-9/]+)",outputstr,flags=re.I|re.M)
        if len(destinationportlist) == 1:
            returndict[session]['destinationports']=destinationportlist[0]
        sourceintvlan=outputstr.split('source')
        if len(sourceintvlan) != 3:
            continue
        sourceintf=sourceintvlan[1]
        sourcevlan=sourceintvlan[2]
        txlist=re.findall("tx[ \t]+:[ \t]+([^ \t\r\n]+)",sourceintf,flags=re.I|re.M)
        if len(txlist) == 1:
            returndict[session]['sourceintftx']=txlist[0]
        rxlist=re.findall("rx[ \t]+:[ \t]+([^ \t\r\n]+)",sourceintf,flags=re.I|re.M)
        if len(rxlist) == 1:
            returndict[session]['sourceintfrx']=txlist[0]
        bothlist=re.findall("both[ \t]+:[ \t]+([^ \t\r\n]+)",sourceintf,flags=re.I|re.M)
        if len(bothlist) == 1:
            returndict[session]['sourceintfboth']=bothlist[0]
        txlist=re.findall("tx[ \t]+:[ \t]+([^ \t\r\n]+)",sourcevlan,flags=re.I|re.M)
        if len(txlist) == 1:
            returndict[session]['sourcevlantx']=txlist[0]
        rxlist=re.findall("rx[ \t]+:[ \t]+([^ \t\r\n]+)",sourcevlan,flags=re.I|re.M)
        if len(rxlist) == 1:
            returndict[session]['sourcevlanrx']=txlist[0]
        bothlist=re.findall("both[ \t]+:[ \t]+([^ \t\r\n]+)",sourcevlan,flags=re.I|re.M)
        if len(bothlist) == 1:
            returndict[session]['sourcevlanboth']=bothlist[0]

    return returndict

def getLtlFormInterface(hdl,log,interface):
 
    #Returns the ltl index for the given interface

    msg='Fetch ltl index for interface {0} on switch {1}'.format(interface,hdl)
    log.info(msg)
    sw_cmd='show system internal ethpm info interface {0} | inc LTL'.format(interface)
    output=hdl.execute(sw_cmd)
    ltl=re.findall('LTL\((0x[0-9]+[a-f]+)\)',output,re.I)
    if len(ltl):
        return ltl[0]
    else :
        msg='No ltl index was found for interface {0} on {1}'.format(interface,hdl)
        print(msg)
        log.info(msg)
        return ltl


def getIgmpSnoopingGroupsDict(hdl,log,*args):

    #Returns the dictionary of igmp snooping groups info
    #(vlan,source,group,version,type) is key
    #e.g.
    #Type: S - Static, D - Dynamic, R - Router port, F - Fabricpath core port
    #Vlan  Group Address      Ver  Type  Port list
    #10    */*                -    R     Eth3/23 Vlan10
    #10    225.0.0.0          v2   
    #        110.0.0.100           S     Eth3/23 
    #10    225.0.0.1          v2   D     Eth3/24
    #Returned dictionary:
    #{('10', '110.0.0.100', '225.0.0.0', 'v3', 'S'): ['Eth3/23'], ('10', '*', '225.0.0.1', 'v2', 'D'): ['Eth3/24'], ('10', '*', '*', '-', 'R'): ['Eth3/23', 'Vlan10'], ('10', '*', '225.0.0.0', 'v2', ''): []}

    msg='Fetch igmp snooping groups info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammar={}
    arggrammar['group']='-type str'
    arggrammar['source']='-type str'
    arggrammar['vlan']='-type str'
    arggrammar['omf_only']='-type bool -default False '
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    type='(?:S|D|R|F)'
    version='(?:v1|v2|v3|\-)'
    vlan='[0-9]+'
    interfaces='(?:{0}\s*)+'.format(rex.INTERFACE_NAME)
    dict={}
    sw_cmd='show ip igmp snooping groups'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getIgmpSnoopingGroupsDict"
         print (msg)
         log.info(msg)
         return {}
    if ns.group:
        sw_cmd+=' '+ns.group
    if ns.source:
        sw_cmd+=' '+ns.source
    if ns.vlan:
        sw_cmd+=' vlan '+ns.vlan    
    if ns.omf_only:
        sw_cmd+=' | inc " R " '
    output=hdl.execute(sw_cmd)
    output=re.sub('R\s','  ',output)
    output=getUnwrappedTable(output,[33,50]) 
    output_list=output.splitlines()

   
    #Get OMF entry 
    omf='({0})\s+\*\/\*\s+({1})\s+({2})'.format(vlan,version,interfaces)
    omf_entries=re.findall(omf,output,re.I)
    for match in omf_entries:
        dict[match[0],'*','*',match[1],'R']=match[2].split()
    
    for line in output_list:
        line=line.strip()
        #Get (*,g) entry
        match=re.search('({0})\s+({1})\s+({2})\s*((?:{3}|))\s*((?:{4}|))'.format(vlan,rex.IP_ADDRESS,version,type,interfaces),line,re.I)
        if match:
           vlan_match=match.group(1)
           grp_match=match.group(2)
           ver_match=match.group(3)
           type_match=match.group(4)
           int_match=match.group(5)
           tmp={(vlan_match,'*',grp_match,ver_match,type_match):int_match.split()}
           dict.update(tmp)
        #Get (*,g) entry with different type
        elif re.search('^({0})\s*({1})'.format(type,interfaces),line,re.I):
           match=re.search('({0})\s*({1})'.format(type,interfaces),line,re.I)
           type_match=match.group(1)
           int_match=match.group(2)
           tmp={(vlan_match,'*',grp_match,ver_match,type_match):int_match.split()}
           dict.update(tmp)
        #Get (s,g) entry and its vlan & grp_addr are from previous (*,g) entry
        elif re.search('^({0})\s+({1})\s+({2})'.format(rex.IP_ADDRESS,type,interfaces),line,re.I):

           match=re.search('^({0})\s+({1})\s+({2})'.format(rex.IP_ADDRESS,type,interfaces),line,re.I)
           src_match=match.group(1)
           type_match=match.group(2)
           int_match=match.group(3)
           tmp={(vlan_match,src_match,grp_match,'v3',type_match):int_match.split()}
           dict.update(tmp)
    return dict

def getIgmpGroupsDict(hdl,log,*args):

    #Returns the dictionary of igmp groups info
    #(source,group,type,interface) is key
    #{'last_reporter','up_time','expires'} are the 2nd-level keys
    #e.g.
    #Group Address      Type Interface           Uptime    Expires   Last Reporter
    #225.0.0.0          D    Ethernet3/47        00:01:02  00:03:17  47.0.0.3
    #225.0.0.0          D    Vlan10              00:01:02  00:04:19  110.0.0.2
    #225.0.0.1          D    Ethernet3/48        00:01:02  00:03:17  48.0.0.2
    #225.0.0.1          S    Vlan10              00:02:44  never     110.0.0.1
    #  47.0.0.2         S    Ethernet3/47        00:02:23  never     47.0.0.1
    #
    #Returned dictionary:
    #{('*', '225.0.0.0', 'D', 'Eth3/47'): {'Uptime': '00:01:31', 'Expires': '00:04:00', 'Last_Reporter': '47.0.0.3'}, ('*', '225.0.0.0', 'D', 'Vlan10'): {'Uptime': '00:01:31', 'Expires': '00:03:50', 'Last_Reporter': '110.0.0.2'}, ('*', '225.0.0.1', 'S', 'Vlan10'): {'Uptime': '00:03:14', 'Expires': 'never', 'Last_Reporter': '110.0.0.1'}, ('47.0.0.2', '225.0.0.1', 'S', 'Eth3/47'): {'Uptime': '00:02:53', 'Expires': 'never', 'Last_Reporter': '47.0.0.1'}, ('*', '225.0.0.1', 'D', 'Eth3/48'): {'Uptime': '00:01:31', 'Expires': '00:04:06', 'Last_Reporter': '48.0.0.2'}}

    msg='Fetch igmp groups info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['group']='-type str'
    arggrammer['source']='-type str'
    arggrammer['interface']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    type='S|D|L|T'
    dict={}
    sw_cmd='show ip igmp groups'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getIgmpGroupsDict"
         print (msg)
         log.info(msg)
         return {}
    if ns.group:
        sw_cmd+=' '+ns.group
    if ns.source:
        sw_cmd+=' '+ns.source
    if ns.interface:
        sw_cmd+=' '+ns.interface    
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    output_list=output.splitlines()

    for line in output_list:
        #Get a line with group address only, g is used for (s,g) entry
        match=re.search('^({0})$'.format(rex.IP_ADDRESS),line,re.I)
        if match:
           grp_match=match.group(1)
        #Get (*,g) entry starting with group address
        elif re.search('^({0}) +({1}) +({2}) +({3}) +({4}) +({5})'.format(rex.IP_ADDRESS,type,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME,rex.IP_ADDRESS),line,re.I):
           match=re.search('^({0}) +({1}) +({2}) +({3}) +({4}) +({5})'.format(rex.IP_ADDRESS,type,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME,rex.IP_ADDRESS),line,re.I)
           grp_match=match.group(1)
           type_match=match.group(2)
           int_match=normalizeInterfaceName(log,match.group(3))
           up_match=match.group(4)
           xp_match=match.group(5)
           rp_match=match.group(6)
           tmp={('*',grp_match,type_match,int_match):{'Last_Reporter':rp_match,'Uptime':up_match,'Expires':xp_match}}
           dict.update(tmp)
        #Get (s,g) entry starting with space and its grp_addr are from previous line
        elif re.search('^ +({0}) +({1}) +({2}) +({3}) +({4}) +({5})'.format(rex.IP_ADDRESS,type,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME,rex.IP_ADDRESS),line,re.I):
           match=re.search('^ +({0}) +({1}) +({2}) +({3}) +({4}) +({5})'.format(rex.IP_ADDRESS,type,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME,rex.IP_ADDRESS),line,re.I)
           src_match=match.group(1)
           type_match=match.group(2)
           int_match=normalizeInterfaceName(log,match.group(3))
           up_match=match.group(4)
           xp_match=match.group(5)
           rp_match=match.group(6)
           tmp={(src_match,grp_match,type_match,int_match):{'Last_Reporter':rp_match,'Uptime':up_match,'Expires':xp_match}}
           dict.update(tmp)
    return dict

def getPimNeighborDict(hdl,log,*args):

    #Returns the dictionary of pim neighbor info
    #Neighbor interface IP address is key
    #Interface, uptime, expires, dr-priority, bidir, bfd-state are the second level keys
    #e.g.
    #Neighbor        Interface            Uptime    Expires   DR       Bidir-  BFD
    #                                                         Priority Capable State
    #12.0.0.1        Ethernet3/22         00:16:41  00:01:36  1        yes     Up
    #24.0.0.3        Ethernet3/24         01:06:49  00:01:34  0        no     Down
    #Returned dictionary:
    #{'24.0.0.3': {'bidir': 'no', 'uptime': '01:06:49', 'expires': '00:01:34', 'dr-priority': '0', 'bfd_state': 'Down', 'interface': 'Ethernet3/24'}, '12.0.0.1': {'bidir': 'yes', 'uptime': '00:16:41', 'expires': '00:01:36', 'dr-priority': '1', 'bfd_state': 'Up', 'interface': 'Ethernet3/22'}}


    msg='Fetch pim neighbor info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['neighbor']='-type str'
    arggrammer['interface']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    priority='[0-9]+'
    bidir='yes|no'
    state='Up|Down|n/a'
    dict={}
    sw_cmd='show ip pim neighbor'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getPimNeighborDict"
         print (msg)
         log.info(msg)
         return {}
    if ns.neighbor and ns.interface:
        msg='Invalid arguments in method:getPimNeighborDict:-neighbor & -interface are exclusive'
        print (msg)
        log.info(msg)
        return {}
    if ns.neighbor:
        sw_cmd+=' '+ns.neighbor
    if ns.interface:
        sw_cmd+=' '+ns.interface    
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    
    pattern='({0}) +({1}) +({2}) +({3}) +({4}) +({5}) +({6})'.format(rex.IP_ADDRESS,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME,priority,bidir,state)
    neighbor_list=re.findall(pattern,output,re.I)
    if len(neighbor_list):
        dict= convertListToDict(neighbor_list,['neighbor','interface','uptime','expires','dr-priority','bidir','bfd_state'],'neighbor')

    return dict

def getMsdpPeerDict(hdl,log,*args):

    #Returns the dictionary of MSDP peer info
    #sample output:
    #OrderedDict([('56.0.0.6', OrderedDict([('vrf', 'default'), ('as', '0'), ('local_addr', '56.0.0.5'), ('local_intf', 'Eth4/41'), ('description', 'insieme'), ('connection_status', 'Established'), ('uptime/downtime', '00:26:55'), ('password', 'set'), ('keepalive_interval', '60'), ('keepalive_timeout', '90'), ('reconnection_interval', '10'), ('sa_in_policy', 'msdp_policy'), ('sa_out_policy', 'msdp_policy'), ('sa_limit', '10'), ('mesh_group', 'my_peers'), ('last_message', '00:00:42'), ('in_sas', '0'), ('out_sas', '0'), ('in_sa_requests', '0'), ('out_sa_requests', '0'), ('in_sa_responses', '0'), ('out_sa_responses', '0'), ('keepalives', '179'), ('notifications', '180'), ('rpf_check_failures', '0'), ('cache_lifetime', '0'), ('established_transitions', '0'), ('connection_attempts', '00:03:30'), ('discontinuity_time', '5')]))])

    msg='Fetch MSDP peer detail info on switch {0}'.format(hdl.switchName)
    log.info(msg)

    arggrammer={}
    arggrammer['peer']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    msdp_peer_dict={}
    sw_cmd='show ip msdp peer'
    if ns.peer:
        sw_cmd+=' {0}'.format(ns.peer)

    output=hdl.execute(sw_cmd)
    pattern='MSDP peer ({0}) for VRF "(.*?)"\s+AS ([0-9]+), local address: ({0}) \(({1})\)\s+\Description: +(.*?)\s+Connection status: (.*?)\s+Uptime\(Downtime\): ({2})\s+(?:Last reset reason: .*?\s+)?Password: (set|not set)\s+Keepalive Interval: ([0-9]+) sec\s+Keepalive Timeout: ([0-9]+) sec\s+Reconnection Interval: ([0-9]+) sec\s+Policies:\s+SA in: (.*?), SA out: (.*?)\s+SA limit: ([0-9]+|unlimited)\s+Member of mesh-group: (.*?)\s+Statistics \(in/out\):\s+Last messaged received: ({2}|never)\s+SAs: ([0-9]+)/([0-9]+), SA-Requests: ([0-9]+)/([0-9]+), SA-Responses: ([0-9]+)/([0-9]+)\s+Keepalives: ([0-9]+)/([0-9]+), Notifications: ([0-9]+)/([0-9]+)\s+RPF check failures: ([0-9]+)\s+Cache Lifetime: ({2})\s+Established Transitions: ([0-9]+)\s+Connection Attempts: ([0-9]+)\s+Discontinuity Time: ({2})'.format(rex.IP_ADDRESS,rex.INTERFACE_NAME,rex.UPTIME)
    match=re.findall(pattern,output,re.I|re.DOTALL)
    if match:
        msdp_peer_dict=convertListToDict(match,['peer','vrf','as','local_addr','local_intf','description','connection_status','uptime/downtime','password','keepalive_interval','keepalive_timeout','reconnection_interval','sa_in_policy','sa_out_policy','sa_limit','mesh_group','last_message','in_sas','out_sas','in_sa_requests','out_sa_requests','in_sa_responses','out_sa_responses','keepalives','notifications','rpf_check_failures','cache_lifetime','established_transitions','connection_attempts','discontinuity_time'],'peer')

    return msdp_peer_dict


def getPimInterfaceDetailDict(hdl,log,*args):

    #Returns the dictionary of pim interface info
    #pim interface stats will be returned only if stats=True
    #Sample Returned dictionary:
    #{'checksum_error_cnt': '0', 'ip_addr': '45.1.1.5', 'hello_cnt': '473/470', 'neighbor_count': '1', 'jp_interval': '1', 'df_backoff_cnt': '0/0', 'hello_interval': '30', 'df_winner_cnt': '0/0', 'auth_fail_cnt': '0', 'df_pass_cnt': '0/0', 'config_dr_priority': '1', 'df_offer_cnt': '0/0', 'bfd': 'no', 'assert_cnt': '0/0', 'jp_inbound_policy': 'jp_route_map', 'join_no_rp_cnt': '0/0', 'jp_outbound_policy': 'jp_route_map', 'pkt_len_error_cnt': '0', 'rpf_jp_cnt': '0', 'ip_subnet': '45.1.1.0/24', 'invalid_pkt_cnt': '0/0', 'neighbor_policy': 'pim_neigh_policy', 'non_nbr_pkt_cnt': '0', 'neighbor_holdtime': '105', 'dr': '45.1.1.6', 'hello_authentication': 'enabled', 'dr_priority': '1', 'border_interface': 'no', 'graft_cnt': '0/0', 'graft_ack_cnt': '0/0', 'join_ssm_bidir_cnt': '0/0', 'bad_ver_pkt_cnt': '0', 'genid': '0x1d53ef96', 'jp_cnt': '0/0', 'self_pkt_cnt': '0'}

    msg='Fetch pim interface detail info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['interface']='-type str -required True'
    arggrammer['stats']='-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    pim_dict={}
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getPimInterfaceDetailDict"
         print (msg)
         log.info(msg)
         return {}

    sw_cmd='show ip pim interface {0}'.format(ns.interface)
    output=hdl.execute(sw_cmd)
    eol='[\r\n\t ]+'
    subnet='{0}\/[0-9]+'.format(rex.IP_ADDRESS)
    #pattern='IP address: ({0}), IP subnet: ({1}){2}PIM DR: ({0}), DR\'s priority: ([0-9]+){2}PIM neighbor count: ([0-9]+){2}PIM hello interval: ([0-9]+) secs.*PIM neighbor holdtime: ([0-9]+) (?:secs|ms){2}PIM configured DR priority: ([0-9]+){2}PIM border interface: (yes|no){2}PIM GenID sent in Hellos: (0x[0-9a-f]+){2}PIM Hello MD5-AH Authentication: (disabled|enabled){2}PIM Neighbor policy: ([^ \r\n\t]+).*{2}PIM Join-Prune inbound policy: ([^ \r\n\t]+).*{2}PIM Join-Prune outbound policy: ([^ \r\n\t]+).*{2}PIM Join-Prune interval: ([0-9]+) minutes.*PIM BFD enabled: (yes|no)'.format(rex.IP_ADDRESS,subnet,eol)
    pattern='IP address: ({0}), IP subnet: ({1}){2}PIM DR: ({0}), DR\'s priority: ([0-9]+){2}PIM neighbor count: ([0-9]+){2}PIM hello interval: ([0-9]+) secs.*PIM neighbor holdtime: ([0-9]+) (?:secs|ms){2}PIM configured DR priority: ([0-9]+){2}PIM configured DR delay: ([0-9]+) secs{2}PIM border interface: (yes|no){2}PIM GenID sent in Hellos: (0x[0-9a-f]+){2}PIM Hello MD5-AH Authentication: (disabled|enabled){2}PIM Neighbor policy: ([^ \r\n\t]+).*{2}PIM Join-Prune inbound policy: ([^ \r\n\t]+).*{2}PIM Join-Prune outbound policy: ([^ \r\n\t]+).*{2}PIM Join-Prune interval: ([0-9]+) minutes.*PIM BFD enabled: (yes|no)'.format(rex.IP_ADDRESS,subnet,eol)
    match=re.search(pattern,output,re.I|re.DOTALL)
    if match:
        pim_dict['ip_addr']=match.group(1)
        pim_dict['ip_subnet']=match.group(2)
        pim_dict['dr']=match.group(3)
        pim_dict['dr_priority']=match.group(4)
        pim_dict['neighbor_count']=match.group(5)
        pim_dict['hello_interval']=match.group(6)
        pim_dict['neighbor_holdtime']=match.group(7)
        pim_dict['config_dr_priority']=match.group(8)
        pim_dict['config_dr_delay']=match.group(9)
        pim_dict['border_interface']=match.group(10)
        pim_dict['genid']=match.group(11)
        pim_dict['hello_authentication']=match.group(12)
        pim_dict['neighbor_policy']=match.group(13)
        pim_dict['jp_inbound_policy']=match.group(14)
        pim_dict['jp_outbound_policy']=match.group(15)
        pim_dict['jp_interval']=match.group(16)
        pim_dict['bfd']=match.group(17)
    else:
        return {}

    if not ns.stats:
        return pim_dict

    count='[0-9]+\/[0-9]+'
    pattern='Hellos: ({0}), JPs: ({0}), Asserts: ({0}){1}Grafts: ({0}), Graft-Acks: ({0}){1}DF-Offers: ({0}), DF-Winners: ({0}), DF-Backoffs: ({0}), DF-Passes: ({0}){1}Errors:{1}Checksum errors: ([0-9]+), Invalid packet types\/DF subtypes: ({0}){1}Authentication failed: ([0-9]+){1}Packet length errors: ([0-9]+), Bad version packets: ([0-9]+), Packets from self: ([0-9]+){1}Packets from non-neighbors: ([0-9]+){1}JPs received on RPF-interface: ([0-9]+){1}\(\*,G\) Joins received with no\/wrong RP: ({0}){1}\(\*,G\)\/\(S,G\) JPs received for SSM/Bidir groups: ({0})'.format(count,eol)
    match=re.search(pattern,output,re.I)
    if match:
        pim_dict['hello_cnt']=match.group(1)
        pim_dict['jp_cnt']=match.group(2)
        pim_dict['assert_cnt']=match.group(3)
        pim_dict['graft_cnt']=match.group(4)
        pim_dict['graft_ack_cnt']=match.group(5)
        pim_dict['df_offer_cnt']=match.group(6)
        pim_dict['df_winner_cnt']=match.group(7)
        pim_dict['df_backoff_cnt']=match.group(8)
        pim_dict['df_pass_cnt']=match.group(9)
        pim_dict['checksum_error_cnt']=match.group(10)
        pim_dict['invalid_pkt_cnt']=match.group(11)
        pim_dict['auth_fail_cnt']=match.group(12)
        pim_dict['pkt_len_error_cnt']=match.group(13)
        pim_dict['bad_ver_pkt_cnt']=match.group(14)
        pim_dict['self_pkt_cnt']=match.group(15)
        pim_dict['non_nbr_pkt_cnt']=match.group(16)
        pim_dict['rpf_jp_cnt']=match.group(17)
        pim_dict['join_no_rp_cnt']=match.group(18)
        pim_dict['join_ssm_bidir_cnt']=match.group(19)

    return pim_dict
        
def getPimInterfaceDict(hdl,log,*args):

    #Returns the dictionary of pim interface info
    #Interface name is key
    #e.g.
    #Interface            IP Address      PIM DR Address  Neighbor  Border
    #                                                     Count     Interface
    #Ethernet3/21         21.0.0.2        21.0.0.2        0         no
    #Ethernet3/22         12.0.0.2        12.0.0.2        1         no
    #Ethernet3/24         24.0.0.2        24.0.0.2        1         no
    #Returned dictionary:
    #{'Ethernet3/21': {'ip': '21.0.0.2', 'neighbor_count': '0', 'dr': '21.0.0.2', 'border_interface': 'no'}, 'Ethernet3/22': {'ip': '12.0.0.2', 'neighbor_count': '1', 'dr': '12.0.0.2', 'border_interface': 'no'}, 'Ethernet3/24': {'ip': '24.0.0.2', 'neighbor_count': '1', 'dr': '24.0.0.2', 'border_interface': 'no'}}

    msg='Fetch pim interface info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    count='[0-9]+'
    border='yes|no'
    dict={}
    sw_cmd='show ip pim interface brief'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getPimInterfaceDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
  
    pattern='({0}) +({1}) +({1}) +({2}) +({3})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS,count,border)
    interface_list=re.findall(pattern,output,re.I)
    if (len(interface_list)):
        dict=convertListToDict(interface_list,['interface','ip','dr','neighbor_count','border_interface'],'interface')

    return dict
     

def getIgmpInterfaceDict(hdl,log,*args):
    #Returns the dictionary of igmp interface info
    #Interface name is key
    #e.g.
    #Interface            IP Address      IGMP Querier    Membership  Version
    #                                                     Count
    #Ethernet3/21         21.0.0.2        21.0.0.2        3           v2
    #Ethernet3/22         12.0.0.2        12.0.0.1        1           v2
    #Ethernet3/24         24.0.0.2        24.0.0.2        0           v2
    #Returned dictionary:
    #{'Ethernet3/21': {'ip': '21.0.0.2', 'version': 'v2', 'membership_count': '3', 'querier': '21.0.0.2'}, 'Ethernet3/22': {'ip': '12.0.0.2', 'version': 'v2', 'membership_count': '1', 'querier': '12.0.0.1'}, 'Ethernet3/24': {'ip': '24.0.0.2', 'version': 'v2', 'membership_count': '0', 'querier': '24.0.0.2'}}

    msg='Fetch igmp interface info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    count='[0-9]+'
    version='v[123]'
    dict={}
    sw_cmd='show ip igmp interface brief'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getIgmpInterfaceDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
  
    pattern='({0}) +({1}) +({1}) +({2}) +({3})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS,count,version)
    interface_list=re.findall(pattern,output,re.I)
    if (len(interface_list)):
        dict=convertListToDict(interface_list,['interface','ip','querier','membership_count','version'],'interface')

    return dict

def getMrouteCountDict(hdl,log,*args):
    #Returns the dictionary of mroute count info
    #e.g.
    #Total number of routes: 3
    #Total number of (*,G) routes: 1
    #Total number of (S,G) routes: 1
    #Total number of (*,G-prefix) routes: 1
    #Group count: 1, rough average sources per group: 1.0
    #Returned Dictionary:
    #{'group_count': '1', 'source_per_group': '1.0', '(*,G)_routes': '1', 'Total': '3', '(S,G)_routes': '1', '(*,G-prefix)_routes': '1'}


    msg='Fetch mroute count info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    dict={}
    sw_cmd='show ip mroute summary count'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getMrouteCountDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    if (re.search('Total number of routes: +([0-9]+)',output,re.I)):
        dict={'Total':re.search('Total number of routes: +([0-9]+)',output,re.I).group(1)}
    if (re.search('Total number of \(\*,G\) routes: +([0-9]+)',output,re.I)):
        tmp={'(*,G)_routes':re.search('Total number of \(\*,G\) routes: +([0-9]+)',output,re.I).group(1)}
        dict.update(tmp)
    if (re.search('Total number of \(S,G\) routes: +([0-9]+)',output,re.I)):
        tmp={'(S,G)_routes':re.search('Total number of \(S,G\) routes: +([0-9]+)',output,re.I).group(1)}
        dict.update(tmp)
    if (re.search('Total number of \(\*,G-prefix\) routes: +([0-9]+)',output,re.I)):
        tmp={'(*,G-prefix)_routes':\
                re.search('Total number of \(\*,G-prefix\) routes: +([0-9]+)',output,re.I).group(1)}
        dict.update(tmp)
    if (re.search('Group count: +([0-9]+)',output,re.I)):
        tmp={'group_count':re.search('Group count: +([0-9]+)',output,re.I).group(1)}
        dict.update(tmp)
    if (re.search('rough average sources per group: +([0-9]+(\.[0-9]+)?)',output,re.I)):
        tmp={'source_per_group':re.search('rough average sources per group: +([0-9]+(\.[0-9]+)?)',\
                                             output,re.I).group(1)}
        dict.update(tmp)

    return dict
    


def getSupervisorSlotNumber(hdl, log, *args):
    '''Returns the active supervisor slot number as integer.

    With the '-state standby' option, it will return the 
    standby supervisor slot number. Returns 0 if none exists'''
    
    arggrammar={}
    arggrammar['state']='-type str -choices ["active","standby"] -default active'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    slot_number=0

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return slot_number

    if options_namespace.state:
        state=options_namespace.state

    show_output=hdl.execute('show module | grep -i sup | grep ' + state)
    if not show_output:
        log.info('No output for command: show module | grep -i sup | grep ' + state)
    else:
        output=re.search('([0-9]+)[ \t]+.*-SUP.*{0}'.format(state),show_output)
        if not output:
            # workaround to be able to test code on n5k
            output=re.search('^([0-9]+).*N5K.*SUP.*{0}'.format(state),show_output)
            if not output:
                # workaround to be able to test code on n3k
                output=re.search('^([0-9]+)\s+([0-9]+).*Supervisor.*{0}'.format(state),show_output)
                if not output:
                    log.warning('No matching Supervisor found in output of: show module | grep Supervisor ' + \
                        '| grep ' + state)
                else:
                    slot_number=output.group(1)   
            else:
                slot_number=output.group(1)
        else:
            slot_number=output.group(1)

    return slot_number

def getSystemResourcesDict(hdl, log, *args):
    '''Returns dictionary format output of system resources of active sup and standby(if present).

    In addition it can return similar output for other modules as specified
    Return null dictionary for modules that arent available

    Usage:
     sys_resources=getSystemResourcesDict(hdl,log)
     sys_resources=getSystemResourcesDict(hdl,log,'-module 3,4,5')
     sys_resources=getSystemResourcesDict(hdl,log,'-fex 101,102')
    
    Sample return value:
    ^^^^^^^^^^^^^^^^^^^^
    First level key is the slot number
    Second level key is the resource name
    
    1:       <--- slot number
      CPU states: {idle: 87.0%, kernel: 0.9%, user: 12.1%}
      Load average: {1 minute: '1.09', 15 minutes: '1.01', 5 minutes: '1.04'}
      Memory usage: {free: 8353304K, total: 12224800K, used: 3871496K}
    2:
      CPU states: {idle: 97.7%, kernel: 1.5%, user: 0.8%}
      Load average: {1 minute: '0.15', 15 minutes: '0.17', 5 minutes: '0.17'}
      Memory usage: {free: 7797216K, total: 12224800K, used: 4427584K}
    3:
      CPU states: {idle: 85.5%, kernel: 3.5%, user: 11.0%}
      Load average: {1 minute: '0.37', 15 minutes: '0.33', 5 minutes: '0.34'}
      Memory usage: {free: 1275828K, total: 2075796K, used: 799968K}
    4: {}    <--- module 4 not present 
    101:     <--- fex 
      CPU states: {idle: 100.0%, kernel: 0.0%, user: 0.0%}
      Load average: {1 minute: '0.01', 15 minutes: '0.07', 5 minutes: '0.12'}
      Memory usage: {free: 0K, total: 515792K, used: 515792K}'''
    
    arggrammar={}
    arggrammar['module']='-type str -format [0-9,]+'
    arggrammar['fex']='-type str -format [0-9,]+'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    system_resource_dict={}

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return system_resource_dict

    command='show system resources | no-more'
    device_list=[]

    if options_namespace.module:
        module=options_namespace.module
        for device_id in str.split(module,','):
            device_list.append((device_id,'module'))
    if options_namespace.fex:
        fex=options_namespace.fex
        for device_id in str.split(fex,','):
            device_list.append((device_id,'fex'))
    if hdl.device_type == 'sTOR':
        device_list=[('1','active')]
        #device_list=[('1','active'), ('1','module')]
    elif hdl.device_type == 'EOR':
        # List of supervisor slots
        for sup_state in ['active','standby']:
            device_id=getSupervisorSlotNumber(hdl,log,'-state ' + sup_state)
            if device_id==0:
                continue
            # If sup slot was passed as a module then overwrite it 
            # such that we can do proper checks for success of 'attach' command
            try:
                index=[dev[0] for dev in device_list].index(device_id)
            except:
                device_list.append((device_id,sup_state))
            else:
                device_list[index]=(device_id,sup_state)

    for device in device_list:
        device_id=int(device[0])
        device_type=device[1]
        system_resource_dict[device_id]={}

        if device_type=='active':
            show_output=hdl.execute('show system resources')
        elif device_type=='standby':
            show_output=hdl.execute(command,'-{0}'.format(device_type))
        else:
            show_output=hdl.execute(command,'-{0} {1}'.format(device_type,device_id))

        if not show_output:
            log.warning('No output in slot {0} for command: show system resources'.format(device_id))
            continue

        system_resource_dict[device_id]['Load average']={}
        load_averages=re.search('Load average[ \t:]+1 minute:[ \t]+([0-9.]+)[ \t]+5 minutes:[ \t]+' + \
            '([0-9.]+)[ \t]+15 minutes:[ \t]+([0-9.]+)',show_output)
        if load_averages:
            system_resource_dict[device_id]['Load average']['1 minute']=load_averages.group(1)
            system_resource_dict[device_id]['Load average']['5 minutes']=load_averages.group(2)
            system_resource_dict[device_id]['Load average']['15 minutes']=load_averages.group(3)

        system_resource_dict[device_id]['CPU states']={}
        cpu_states=re.search('CPU states[ \t:]+([0-9.%]+) user,[ \t]+([0-9.%]+) kernel,[ \t]+' + \
            '([0-9.%]+) idle',show_output)
        if cpu_states:
            system_resource_dict[device_id]['CPU states']['user']=cpu_states.group(1)
            system_resource_dict[device_id]['CPU states']['kernel']=cpu_states.group(2)
            system_resource_dict[device_id]['CPU states']['idle']=cpu_states.group(3)

        system_resource_dict[device_id]['CPU core states']={}
        cpu_core_states=re.findall('CPU([0-9]+) states[ \t:]+([0-9.%]+) user,[ \t]+([0-9.%]+) kernel,[ \t]+' + \
            '([0-9.%]+) idle',show_output)
        for cpu_core in cpu_core_states:
            cpu_core_id=cpu_core[0]
            system_resource_dict[device_id]['CPU core states'][cpu_core_id]={}
            system_resource_dict[device_id]['CPU core states'][cpu_core_id]['user']=cpu_core[1]
            system_resource_dict[device_id]['CPU core states'][cpu_core_id]['kernel']=cpu_core[2]
            system_resource_dict[device_id]['CPU core states'][cpu_core_id]['idle']=cpu_core[3]

        system_resource_dict[device_id]['Memory usage']={}
        memory_usage=re.search('Memory usage[ \t:]+([0-9K]+) total,[ \t]+([0-9K]+) used,[ \t]+' + \
            '([0-9K]+) free',show_output)
        if memory_usage:
            system_resource_dict[device_id]['Memory usage']['total']=memory_usage.group(1)
            system_resource_dict[device_id]['Memory usage']['used']=memory_usage.group(2)
            system_resource_dict[device_id]['Memory usage']['free']=memory_usage.group(3)

        if not system_resource_dict[device_id]['Load average'] or\
            not system_resource_dict[device_id]['CPU states'] or\
            not system_resource_dict[device_id]['Memory usage']:
            system_resource_dict.pop(device_id,None)

    return system_resource_dict

#======================================================================================#
# getUserAccountDict - Method to get user accounts and their roles on a DUT
#
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#
# Returned Dictionary Example:
#{'admin': ['network-admin', 'network-operator'], 'test': ['vdc-admin', 'network-admin', 'network-operator'], 'test2': ['network-operator']}
#======================================================================================#
def getUserAccountDict(hdl, log):
    msg="Fetching user-accounts"
    log.info(msg)
    sw_cmd="show user-account"
    output=hdl.execute(sw_cmd)

    pat='user:([^ ]+)\r\n.*\r\n[ \t]+roles:(.+)\r\n'
    user_account_list=re.findall( pat, output, flags=re.M)
    user_account_dict=convertListToDict(user_account_list,['user_id','roles'],['user_id'])
    for usr in user_account_dict.keys():
        user_account_dict[str(usr)]=str(user_account_dict[str(usr)]).split()

    if len(user_account_list)==0:
         msg='No user accounts found'
         log.info(msg)

    msg="User accounts found - {0}".format(user_account_dict.keys())
    log.info(msg)
    return user_account_dict


def getMfdmL2McastDict(hdl,log,*args):
    '''
    Return the dictionary of L2 multicast route info from MFDM
    Sample output:
    {('100', '225.0.0.2', '0.0.0.0'): {'reference_count': '1', 'oif_list': ['Ethernet4/42'], 'oif_index': '11', 'platform_index': '0x7fdc', 'oif_count': '1'}, ('100', '225.0.0.2', '10.10.10.10'): {'reference_count': '2', 'oif_list': ['Ethernet4/41', 'Ethernet4/42', 'Ethernet4/43'], 'oif_index': '10', 'platform_index': '0x7fe2', 'oif_count': '3'}, ('100', '225.0.0.2', 'aggregated'): {'reference_count': '2', 'oif_list': ['Ethernet4/41', 'Ethernet4/42', 'Ethernet4/43'], 'oif_index': '10', 'platform_index': '0x7fe2', 'oif_count': '3'}}
    '''
    msg='Fetch mfdm l2 multicast route info on switch {0}'.format(hdl.switchName)
    log.info(msg)

    arggrammer={}
    arggrammer['vlan']='-type str'
    arggrammer['group']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    mfdm_dict={}
    sw_cmd="show forwarding distribution l2 multicast"
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getMfdmL2McastDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vlan:
        sw_cmd+=' vlan '+ns.vlan
    if ns.group:
        sw_cmd+=' group '+ns.group
    sw_cmd+=" | grep -v Vpc"
    output=hdl.execute(sw_cmd)
    #split output with an empty new line
    output_list=output.split('\r\n\r\n')

    EOL='[\r\n\t ]+'
    pattern="Vlan: ([0-9]+), Group: ({0}), Source: ({0}){1}Outgoing Interface List Index: ([0-9]+){1}Reference Count: ([0-9]+){1}Platform Index: (0x[0-9a-f]+){1}Number of Outgoing Interfaces: ([0-9]+)"\
            .format(rex.IP_ADDRESS,EOL)
    aggr_pattern="Vlan: ([0-9]+), Aggregated Group: ({0}), Source: 0\.0\.0\.0{1}Outgoing Interface List Index: ([0-9]+){1}Reference Count: ([0-9]+){1}Platform Index: (0x[0-9a-f]+){1}Number of Outgoing Interfaces: ([0-9]+)"\
            .format(rex.IP_ADDRESS,EOL)
    for route in output_list:
        match=re.search(pattern,route,re.I)
        aggr_match=re.search(aggr_pattern,route,re.I)
        value={}

        if match:
            key=(match.group(1),match.group(2),match.group(3))
            value={'oif_index':match.group(4),'reference_count':match.group(5),'platform_index':match.group(6),'oif_count':match.group(7)}
        elif aggr_match:
            key=(aggr_match.group(1),aggr_match.group(2),'aggregated')
            value={'oif_index':aggr_match.group(3),'reference_count':aggr_match.group(4),'platform_index':aggr_match.group(5),'oif_count':aggr_match.group(6)}

        oif_list=re.findall(rex.INTERFACE_NAME,route,re.I|re.DOTALL)
        if value:
            value.update({'oif_list':oif_list})
            mfdm_dict[key]=value
        
    return mfdm_dict

def getMrouteDict(hdl,log,*args):

    #Returns the dictionary of mroute info
    #(source,group) is key
    #e.g.
    #(*, 225.0.0.0/32), uptime: 1d02h, ip pim igmp static 
    #  Incoming interface: loopback0, RPF nbr: 1.1.1.1
    #  Outgoing interface list: (count: 2)
    #  Ethernet3/23, uptime: 00:00:14, static
    #  Ethernet3/24, uptime: 05:44:00, igmp

    #(110.0.0.2/32, 225.0.0.0/32), uptime: 00:09:52, ip mrib pim 
    #  Incoming interface: Null, RPF nbr: 0.0.0.0, internal
    #  Outgoing interface list: (count: 2)
    #  Ethernet3/23, uptime: 00:00:14, mrib
    #  Ethernet3/24, uptime: 00:09:52, mrib

    #(*, 232.0.0.0/8), uptime: 1d07h, pim ip 
    #  Incoming interface: Null, RPF nbr: 0.0.0.0
    #  Outgoing interface list: (count: 0)
    #Returned dictionary:
    #{('110.0.0.2', '225.0.0.0'): {'rpf_interface': 'Null', 'uptime': '00:09:52', 'oif_count': '2', 'oif_list': ['Eth3/23', 'Eth3/24'], 'rpf_neighbor': '0.0.0.0'}, ('*', '232.0.0.0'): {'rpf_interface': 'Null', 'uptime': '1d07h', 'oif_count': '0', 'oif_list': [], 'rpf_neighbor': '0.0.0.0'}, ('*', '225.0.0.0'): {'rpf_interface': 'loopback0', 'uptime': '1d02h', 'oif_count': '2', 'oif_list': ['Eth3/23', 'Eth3/24'], 'rpf_neighbor': '1.1.1.1'}}

    msg='Fetch ip mroute info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['group']='-type str'
    arggrammer['source']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
    
    owner='static|ip|pim|igmp|mrib|nve'
    dict={}
    sw_cmd='show ip mroute'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getMrouteDict"
         print (msg)
         log.info(msg)
         return {}
    if (ns.source and not ns.group):
         msg="Invalid arguments in method-getMrouteDict:-source should be used together with -group"
         print (msg)
         log.info(msg)
         return {}
    if ns.group:
        sw_cmd+=' '+ns.group
    if ns.source:
        sw_cmd+=' '+ns.source
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    time.sleep(3)
    output=hdl.execute(sw_cmd)
    #split output with an empty new line 
    output_list=output.split('\r\n\r\n')
   
    for group_entry in output_list:
        found=0
        group_list=group_entry.splitlines()
        oif_list=[]
        #Parse a (*,g)/(s,g) group entry
        for line in group_list:
            #(*,g) entry 
            match=re.search('\(*, +({0})\/[0-9]+\), +uptime: ({1}), +(?:{2})'.format(rex.IP_ADDRESS,rex.UPTIME,owner),line,re.I)
            if match:
                src_addr='*'
                grp_addr=match.group(1)
                up_time=match.group(2)
                found=1
            #(*,g) entry for bidir 
            match=re.search('\(*, +({0})\/[0-9]+\), bidir, +uptime: ({1}), +(?:{2})'.format(rex.IP_ADDRESS,rex.UPTIME,owner),line,re.I)
            if match:
                src_addr='*'
                grp_addr=match.group(1)
                up_time=match.group(2)
                found=1
            #(s,g) entry
            if re.search('\(({0})\/32, +({0})\/32\), +uptime: ({1}), +(?:{2})'.format(rex.IP_ADDRESS,rex.UPTIME,owner),line,re.I):
                match=re.search('\(({0})\/32, +({0})\/32\), +uptime: ({1}), +(?:{2})'.format(rex.IP_ADDRESS,rex.UPTIME,owner),line,re.I)
                src_addr=match.group(1)
                grp_addr=match.group(2)
                up_time=match.group(3)
                found=1
            #iif info
            elif re.search('Incoming interface: +({0}), +RPF nbr: +({1})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS),line,re.I):
                match=re.search('Incoming interface: +({0}), +RPF nbr: +({1})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS),line,re.I)
                rpf_int=match.group(1)
                rpf_nbr=match.group(2)
            #oif count
            elif re.search('Outgoing interface list: +\(count: +([0-9]+)\)',line,re.I):
                match=re.search('Outgoing interface list: +\(count: +([0-9]+)\)',line,re.I)
                oif_cnt=match.group(1)
            #oif list info 
            elif re.search('({0}), +uptime: (?:{1}), +(?:{2})'.format(rex.INTERFACE_NAME,rex.UPTIME,owner),line,re.I):
                match=re.search('({0}), +uptime: (?:{1}), +(?:{2})'.format(rex.INTERFACE_NAME,rex.UPTIME,owner),line,re.I)
                oif=match.group(1)
                oif_list.append(oif)
        #Add each group entry to dictionary
        if (found):
            rpf_int=normalizeInterfaceName(log,rpf_int)
            oif_list=normalizeInterfaceName(log,oif_list)
            tmp={(src_addr,grp_addr):{'uptime':up_time,'rpf_interface':rpf_int,'rpf_neighbor':rpf_nbr,'oif_count':oif_cnt,'oif_list':oif_list}}
            dict.update(tmp)
    return dict


def getPimRouteDict(hdl,log,*args):

    #Returns the dictionary of pim route info
    #(source,group) is key
    #e.g.

    #(*, 232.0.0.0/8), expires 00:02:34
    #Incoming interface: Null0, RPF nbr 0.0.0.0
    #Oif-list:       (0) 00000000, timeout-list: (0) 00000000
    #Immediate-list: (0) 00000000, timeout-list: (0) 00000000
    #Sgr-prune-list: (0) 00000000
    #Timeout-interval: 2, JP-holdtime round-up: 3
    #
    #(*, 234.156.208.20/32), RP 2.2.2.2, expires 00:01:33, RP-bit
    #Incoming interface: Null, RPF nbr 0.0.0.0
    #Oif-list: (0) 00000000, timeout-list: (0) 00000000
    #Timeout-interval: 1, JP-holdtime round-up: 3

    #(*, 239.0.0.2/32), RP 0.0.0.0, expires 00:00:43, RP-bit
    #Incoming interface: Null, RPF nbr 0.0.0.0
    #Oif-list: (0) 00000000, timeout-list: (0) 00000000
    #Timeout-interval: 1, JP-holdtime round-up: 3
    #Returned dictionary:
    #{('110.0.0.2', '225.0.0.0'): {'rpf_interface': 'Null', 'uptime': '00:09:52', 'oif_count': '2', 'oif_list': ['Eth3/23', 'Eth3/24'], 'rpf_neighbor': '0.0.0.0'}, ('*', '232.0.0.0'): {'rpf_interface': 'Null', 'uptime': '1d07h', 'oif_count': '0', 'oif_list': [], 'rpf_neighbor': '0.0.0.0'}, ('*', '225.0.0.0'): {'rpf_interface': 'loopback0', 'uptime': '1d02h', 'oif_count': '2', 'oif_list': ['Eth3/23', 'Eth3/24'], 'rpf_neighbor': '1.1.1.1'}}

    msg='Fetch ip pim route info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['group']='-type str'
    arggrammer['source']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
    
    owner='static|ip|pim|igmp|mrib|nve'
    dict={}
    sw_cmd='show ip pim route'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getPimRouteDict"
         print (msg)
         log.info(msg)
         return {}
    if (ns.source and not ns.group):
         msg="Invalid arguments in method-getPimRouteDict:-source should be used together with -group"
         print (msg)
         log.info(msg)
         return {}
    if ns.group:
        sw_cmd+=' '+ns.group
    if ns.source:
        sw_cmd+=' '+ns.source
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    time.sleep(3)
    output=hdl.execute(sw_cmd)
    #split output with an empty new line 
    output_list=output.split('\r\n\r\n')
   
    for group_entry in output_list:
        found=0
        rp_found=0
        sgr_found=0
        group_list=group_entry.splitlines()
        oif_list=[]
        #Parse a (*,g)/(s,g) group entry
#        print group_list
        for line in group_list:
            #(*,g) entry
            match=re.search('\(*, +({0})\/[0-9]+\), +expires ({1})'.format(rex.IP_ADDRESS,rex.UPTIME),line,re.I)
            if match:
                src_addr='*'
                grp_addr=match.group(1)
                expire_time=match.group(2)
#                print 'grp_addr{0}'.format(grp_addr)
#                print 'expire_time{0}'.format(expire_time)
                found=1
            #(*,g) entry 
#            rp='NA'
            match=re.search('\(*, +({0})\/[0-9]+\), +RP ({0}), +expires ({1}), +RP-bit'.format(rex.IP_ADDRESS,rex.UPTIME),line,re.I)
            if match:
                src_addr='*'
                grp_addr=match.group(1)
                expire_time=match.group(3)
                rp=match.group(2)
                rp_found=1
#                print 'grp_addr{0}'.format(grp_addr)
#                print 'rp{0}'.format(rp)
#                print 'expire_time{0}'.format(expire_time)
                found=1
            #(s,g) entry
            if re.search('\(({0})\/32, +({0})\/32\), +expires ({1})'.format(rex.IP_ADDRESS,rex.UPTIME),line,re.I):
                match=re.search('\(({0})\/32, +({0})\/32\), +expires ({1})'.format(rex.IP_ADDRESS,rex.UPTIME),line,re.I)
                src_addr=match.group(1)
                grp_addr=match.group(2)
                expire_time=match.group(3)
#                print 'src_addr{0}'.format(src_addr)
#                print 'grp_addr{0}'.format(grp_addr)
#                print 'expire_time{0}'.format(expire_time)
                found=1
            #(s,g) entry
#            rp='NA'
            if re.search('\(({0})\/32, +({0})\/32\), +RP ({0}), +expires ({1}), +RP-bit'.format(rex.IP_ADDRESS,rex.UPTIME),line,re.I):
                match=re.search('\(({0})\/32, +({0})\/32\), +RP ({0}), +expires ({1}), +RP-bit'.format(rex.IP_ADDRESS,rex.UPTIME),line,re.I)
                src_addr=match.group(1)
                rp=match.group(3)
                grp_addr=match.group(2)
                expire_time=match.group(4)
                rp_found=1
#                print 'rp{0}'.format(rp)
#                print 'src_addr{0}'.format(src_addr)
#                print 'grp_addr{0}'.format(grp_addr)
#                print 'expire_time{0}'.format(expire_time)
                found=1
            #iif info
            if re.search('Incoming interface: +({0}), +RPF nbr +({1})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS),line,re.I):
                match=re.search('Incoming interface: +({0}), +RPF nbr +({1})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS),line,re.I)
                rpf_int=match.group(1)
                rpf_nbr=match.group(2)
#                print 'rpf_int{0}'.format(rpf_int)
#                print 'rpf_nbr{0}'.format(rpf_nbr)
                found=1
            #oif    
            if re.search('Oif-list:       +(\([0-9]+\) [0-9]+), +timeout-list: (\([0-9]+\) [0-9]+)',line,re.I):
                match=re.search('Oif-list:       +(\([0-9]+\) [0-9]+), +timeout-list: (\([0-9]+\) [0-9]+)',line,re.I)
                oif_list=match.group(1)
                oif_timeout_list=match.group(2)
#                print 'oif_list{0}'.format(oif_list)
#                print 'oif_timeout_list{0}'.format(oif_timeout_list)
                found=1
            if re.search('Oif-list: +(\([0-9]+\) [0-9]+), +timeout-list: +(\([0-9]+\) [0-9]+)',line,re.I):
                match=re.search('Oif-list: +(\([0-9]+\) [0-9]+), +timeout-list: +(\([0-9]+\) [0-9]+)',line,re.I)
                oif_list=match.group(1)
                oif_timeout_list=match.group(2)
#                print 'oif_list{0}'.format(oif_list)
#                print 'oif_timeout_list{0}'.format(oif_timeout_list)
                found=1
#            immediate_list='NA'
#            immediate_timeout_list='NA'
            if re.search('Immediate-list: (\([0-9]+\) [0-9]+), +timeout-list: (\([0-9]+\) [0-9]+)',line,re.I):
                match=re.search('Immediate-list: (\([0-9]+\) [0-9]+), +timeout-list: (\([0-9]+\) [0-9]+)',line,re.I)
                immediate_list=match.group(1)
                immediate_timeout_list=match.group(2)
#                print 'immediate_list{0}'.format(immediate_list)
#                print 'immediate_timeout_list{0}'.format(immediate_timeout_list)
                found=1

            if re.search('Sgr-prune-list: (\([0-9]+\) [0-9]+)',line,re.I):
                 match=re.search('Sgr-prune-list: (\([0-9]+\) [0-9]+)',line,re.I)
                 sgr_prune_list=match.group(1)
                 sgr_found=1
#                 print 'sgr_prune_list{0}'.format(sgr_prune_list)
                 found=1
                
            if re.search('Timeout-interval: ([0-9])+, +JP-holdtime round-up: ([0-9]+)',line,re.I):
                match=re.search('Timeout-interval: ([0-9])+, +JP-holdtime round-up: ([0-9]+)',line,re.I)
                timeout_interval=match.group(1)
                jp_holdtime_roundup=match.group(2)
#                print 'timeout_interval{0}'.format(timeout_interval)
#                print 'jp_holdtime_roundup{0}'.format(jp_holdtime_roundup)
                found=1
        #Add each group entry to dictionary
        if (found and rp_found):
            tmp={(src_addr,grp_addr):{'expires':expire_time,'rpf_interface':rpf_int,'rpf_neighbor':rpf_nbr,'oif_list':oif_list, 'oif_timeout_list':oif_timeout_list, 'immediate_list':immediate_list, 'immediate_timeout_list':immediate_timeout_list, 'sgr_prune_list':'NA', 'timeout_interval':timeout_interval, 'jp_holdtime_roundup':jp_holdtime_roundup, 'rp':rp}}
            dict.update(tmp)
        if (found and sgr_found):
            tmp={(src_addr,grp_addr):{'expires':expire_time,'rpf_interface':rpf_int,'rpf_neighbor':rpf_nbr,'oif_list':oif_list, 'oif_timeout_list':oif_timeout_list, 'immediate_list':immediate_list, 'immediate_timeout_list':immediate_timeout_list, 'sgr_prune_list':sgr_prune_list, 'timeout_interval':timeout_interval, 'jp_holdtime_roundup':jp_holdtime_roundup, 'rp':'NA'}}
            dict.update(tmp)

    return dict



def getMtsBuffersSummaryDict(hdl, log, *args):
    '''Returns dictionary format of mts buffers summary of active sup and standby(if present).

    In addition it can return similar output for other modules as specified
    Return null dictionary for modules that arent available
    
    Usage:
     mts_buffers=getMtsBuffersDict(hdl,log)
     mts_buffers=getMtsBuffersDict(hdl,log,'-module 3,4,5')
     mts_buffers=getMtsBuffersDict(hdl,log,'-fex 101,102')

    Sample return value:
    ^^^^^^^^^^^^^^^^^^^^
    First level key is the slot number
    Second level key is a tuple of 'node' and 'sapno'
    Third level key are the queue names
    1:
      (sup, 284): {log_q: 0, npers_q: 0, pers_q: 7, recv_q: 0}
      (sup-1, 284): {log_q: 0, npers_q: 0, pers_q: 2, recv_q: 0}
      (sup-2, 284): {log_q: 0, npers_q: 0, pers_q: 2, recv_q: 0}
      (sup-3, 284): {log_q: 0, npers_q: 0, pers_q: 2, recv_q: 0}
      (sup-4, 284): {log_q: 0, npers_q: 0, pers_q: 2, recv_q: 0}
      (sup-5, 284): {log_q: 0, npers_q: 0, pers_q: 2, recv_q: 0}
      (sup-6, 284): {log_q: 0, npers_q: 0, pers_q: 2, recv_q: 0}
      (sup-7, 284): {log_q: 0, npers_q: 0, pers_q: 2, recv_q: 0}
    3:
      (lc, 376): {log_q: 0, npers_q: 0, pers_q: 0, recv_q: 12}
      (lc, 2062): {log_q: 0, npers_q: 1, pers_q: 0, recv_q: 1}
    4: {}        <--- Module not present
    101: {}      <--- No pending MTS messages'''
    
    arggrammar={}
    arggrammar['module']='-type str -format [0-9,]+'
    arggrammar['fex']='-type str -format [0-9,]+'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    system_mts_summary_dict={}
    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return system_mts_summary_dict

    command='show system internal mts buffers summary'
    system_mts_summary_dict={}
    device_list=[]

    if options_namespace.module:
        module=options_namespace.module
        for device_id in str.split(module,','):
            device_list.append((device_id,'module'))
    if options_namespace.fex:
        fex=options_namespace.fex
        for device_id in str.split(fex,','):
            device_list.append((device_id,'fex'))
    if hdl.device_type == 'sTOR':
        device_list=[('1','active')]
        #device_list=[('1','active'), ('1','module')]
    elif hdl.device_type == 'EOR':
        # List of supervisor slots
        for sup_state in ['active','standby']:
            device_id=getSupervisorSlotNumber(hdl,log,'-state ' + sup_state)
            if device_id==0:
                continue
            # If sup slot was passed as a module then overwrite it 
            # such that we can do proper checks for success of 'attach' command
            try:
                index=[dev[0] for dev in device_list].index(device_id)
            except:
                device_list.append((device_id,sup_state))
            else:
                device_list[index]=(device_id,sup_state)
    else:
        device_list=[('1','active')]

    for device in device_list:
        device_id=int(device[0])
        device_type=device[1]
        system_mts_summary_dict[device_id]={}

        if device_type=='active':
            show_output=hdl.execute(command)
        elif device_type=='standby':
            show_output=hdl.execute(command,'-{0}'.format(device_type))
        else:
            show_output=hdl.execute(command,'-{0} {1}'.format(device_type,device_id))

        if not show_output:
            log.warning('No output in slot {0} for command: {1}'.format(device_id,command))
            continue

        node_list=re.findall('^([^ \t]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)' + \
            '[ \t]+([0-9]+)',show_output,re.M)

        for item in node_list:
            node=item[0]
            sapno=int(item[1])
            system_mts_summary_dict[device_id][(node,sapno)]={}
            system_mts_summary_dict[device_id][(node,sapno)]['recv_q']=int(item[2])
            system_mts_summary_dict[device_id][(node,sapno)]['pers_q']=int(item[3])
            system_mts_summary_dict[device_id][(node,sapno)]['npers_q']=int(item[4])
            system_mts_summary_dict[device_id][(node,sapno)]['log_q']=int(item[5])

        if not system_mts_summary_dict[device_id]:
            system_mts_summary_dict.pop(device_id,None)

    return system_mts_summary_dict


def getUdldNeighborDict(hdl, log, *args):
    '''Returns the UDLD neighbors information.

    Can be used to return the UDLD neighbor of a specific interface

    Usage:
     udld_info=getUdldNeighborDict(hdl,log)
     udld_info=getUdldNeighborDict(hdl,log,'-interface eth1/1')
    
    Sample return value:
    ^^^^^^^^^^^^^^^^^^^^
    First level key is the port name
    Second level keys are 'Device ID', 'Device Name', 'Neighbor State', and 'Port ID'
    
    Ethernet3/1: 
     {Device ID: '1', Device Name: JAF1638AAKC, Neighbor State: bidirectional, 
                 Port ID: Ethernet3/13, CDP Device name: 'N7K7'}
    Ethernet3/2: 
     {Device ID: '1', Device Name: JAF1638AAKC, Neighbor State: bidirectional, 
                 Port ID: Ethernet3/14, CDP Device Name: 'N7K8'}'''

    arggrammar={}
    arggrammar['interface']='-type str'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    udld_neighbors_dict={}

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return udld_neighbors_dict

    if options_namespace.interface:
        command='show udld ' + options_namespace.interface
        show_output=hdl.execute(command)
        if not show_output:
            log.info('No output for command: ' + command)
        else:
            output=re.search('Interface ([a-zA-Z]+[0-9/]+).*Cache Device index:[ \t]+([^ \t\r\n]+)' + \
                '.*Current neighbor state:[ \t]+([^ \t\r\n]+).*Device ID:[ \t]+([^ \t\r\n]+)' + \
                '.*Port ID:[ \t]+([^ \t\r\n]+)' + \
                '.*CDP Device name:[ \t]+([^ \t\r\n]+)',show_output,re.DOTALL)
        if output:
            interface_name=output.group(1)
            udld_neighbors_dict[interface_name]={}
            udld_neighbors_dict[interface_name]['Device Name']=output.group(4)
            udld_neighbors_dict[interface_name]['Device ID']=output.group(2)
            udld_neighbors_dict[interface_name]['Port ID']=output.group(5)
            udld_neighbors_dict[interface_name]['Neighbor State']=output.group(3)
            cdp_name=re.search('([^ ]+)\({0}\)'.format(output.group(4)),output.group(6)).group(1)
            udld_neighbors_dict[interface_name]['CDP Device name']=cdp_name
    else:
        command='show udld neighbors'
        show_output=hdl.execute(command)
        if not show_output:
            log.error('No output for command: ' + command)
            return {}
        else:
            output=re.findall('^([a-zA-Z]+[0-9/]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)' + \
                '[ \t]+([^ \t]+)',show_output,re.M)

        for neighbor in output:
            interface_name=neighbor[0]
            udld_neighbors_dict[interface_name]={}
            udld_neighbors_dict[interface_name]['Device Name']=neighbor[1]
            udld_neighbors_dict[interface_name]['Device ID']=neighbor[2]
            udld_neighbors_dict[interface_name]['Port ID']=neighbor[3]
            udld_neighbors_dict[interface_name]['Neighbor State']=neighbor[4]
            command='show udld ' + interface_name
            show_detail_output=hdl.execute(command)
            if not show_output:
                log.info('No output for command: ' + command)
                cdp_name=''
            else:
                cdp_device_name=re.search('CDP Device name:[ \t]+([^ \t\r\n]+)',\
                    show_detail_output,re.DOTALL)
                if cdp_device_name:
                    cdp_name=re.search('([^ ]+)\({0}\)'.format(neighbor[1]),\
                        cdp_device_name.group(1)).group(1)
                else:
                    log.info('No output for command: ' + command)
                    cdp_name=''
            udld_neighbors_dict[interface_name]['CDP Device name']=cdp_name

    return udld_neighbors_dict


def getHardwareMacAddressTableCount(hdl,log,*args):

    # Get the Hardware MAC address table count
    # Usage: getHardwareMacAddressTableCount(hdl,log, '-module 3 -flag dynamic')
    arggrammar={}
    arggrammar['module']='-type int -required True' 
    arggrammar['address']='-type str'
    arggrammar['flag']='-choices dynamic|static'
    arggrammar['intf']='-type str'
    arggrammar['vlan']='-type int'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    cmd = 'show hardware mac address-table ' + str(parse_output.module)
    if parse_output.flag:
        cmd = cmd + ' ' +  parse_output.flag
    if parse_output.vlan:
        cmd = cmd + ' vlan ' + str(parse_output.vlan)
    if parse_output.intf:
        cmd = cmd + ' interface ' + parse_output.intf
    if parse_output.address:
        cmd = cmd + ' address ' + parse_output.address
    return hdl.execute(cmd + ' | egrep ' + '" +[0-9]+"' + ' | wc lines')

def getFeatureStateDict(hdl,log,*args):

    # Get the Feature State Dict
    # Usage: getFeatureState (hdl,log, '-feature eigrp')
    # Usage: getFeatureState (hdl,log)
    arggrammar={}
    arggrammar['feature']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    cmd = 'show feature' 
    if parse_output.feature:
        if parse_output.feature == 'hsrp':
             parse_output.feature = 'hsrp_engine'
        cmd = cmd + ' | grep -i ' + str(parse_output.feature)
    cmd_out = hdl.execute(cmd)
    pattern = '([A-Za-z0-9_\-]+) +(' + rex.NUM + ') +([enadis]+bled)'
    feat_matchlist=re.findall(pattern, cmd_out)
    return convertListToDict(feat_matchlist,['feature','instance','state'],['feature','instance'])

def getFeatureState(hdl,log,*args):

    # Get the Feature State (enabled/disabled/unknown)
    # return value unkown is an error scenario
    # Usage: getFeatureState (hdl,log, '-feature eigrp -instance 1')
    # Usage: getFeatureState (hdl,log, '-feature eigrp')
    arggrammar={}
    arggrammar['feature']='-type str -required True'
    arggrammar['instance']='-type int -default 1'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    feat_dict=getFeatureStateDict(hdl,log,'-feature ' + parse_output.feature)
    print (feat_dict) 
    if feat_dict != {}:
        return feat_dict[(parse_output.feature,str(parse_output.instance))]
    else:
        log.error ('Unknown state for feature' + str(parse_output.feature))
        return 'unknwon'
    
def getLldpNeighborDict(hdl,log,*args):

    # Get the LLDP neighbor info in dict
    # Eth4/1: {holdtime: '120', peer: N7K2-vdc2, peer_cap: BR, peer_intf: Eth4/13}
    # Eth4/2: {holdtime: '120', peer: N7K2-vdc2, peer_cap: BR, peer_intf: Eth4/14}

    arggrammar={}
    arggrammar['intf']='-type str'
    cmd = 'show lldp neighbor'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.intf:
        cmd = cmd + ' interface ' + parse_output.intf
    pattern = '({0}) +({2}) +({1}) +([BRTCWPSO]+) +({2})'.format(rex.SWITCH_NAME,rex.NUM,rex.PHYSICAL_INTERFACE_NAME)
    cmd_out = hdl.execute(cmd)
    lldp_matchlist=re.findall(pattern, cmd_out)
    return convertListToDict(lldp_matchlist,['peer','intf','holdtime', 'peer_cap', 'peer_intf'],['intf'])

def getLldpNeighborCount (hdl,log,*args):

    # Get the LLDP neighbor count

    arggrammar={}
    arggrammar['intf']='-type str'
    cmd = 'show lldp neighbor'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.intf:
        cmd = cmd + ' interface ' + parse_output.intf
    pattern = '({0}) +({2}) +({1}) +([BRTCWPSO]+) +({2})'.format(rex.SWITCH_NAME,rex.NUM,rex.PHYSICAL_INTERFACE_NAME)
    cmd_out = hdl.execute(cmd)
    lldp_matchlist=re.findall(pattern, cmd_out)
    return len(lldp_matchlist)


def getLoggingLevelDict(hdl, log, *args):
    '''Returns the logging level of each component on active sup and standby(if present).

    Can be used to return the logging level of a given component on any module(s) or fex(s)
    
    Usage:
     log_info=getLoggingLevelDict(hdl,log)
     log_info=getLoggingLevelDict(hdl,log,'-component aaa')
     log_info=getLoggingLevelDict(hdl,log,'-module 3,4 -component aaa')
     log_info=getLoggingLevelDict(hdl,log,'-fex 101,102 -component aaa')

    Sample return value:
    ^^^^^^^^^^^^^^^^^^^^
    First level key is the slot number
    Second level key is the component(process)
    Third level keys are the 'Current' and 'Default' levels of logging
    
    1:
      sysmgr: {Current: '3', Default: '3'}
    3:
      sysmgr: {Current: '3', Default: '3'}
    4: {}    <--- module not present
    101:
      sysmgr: {Current: '3', Default: '3'}'''
   

    arggrammar={}
    arggrammar['component']='-type str'
    arggrammar['module']='-type str -format [0-9,]+ -mandatoryargs component'
    arggrammar['fex']='-type str -format [0-9,]+ -mandatoryargs component'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    logging_level_dict={}

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return logging_level_dict

    command='show logging level'
    component='[^ \t]+'
    if options_namespace.component:
        command=command + ' ' + options_namespace.component
        component=options_namespace.component

    device_list=[]

    if options_namespace.module:
        module=options_namespace.module
        for device_id in str.split(module,','):
            device_list.append((device_id,'module'))
    if options_namespace.fex:
        fex=options_namespace.fex
        for device_id in str.split(fex,','):
            device_list.append((device_id,'fex'))

    # List of supervisor slots
    for sup_state in ['active','standby']:
        device_id=getSupervisorSlotNumber(hdl,log,'-state ' + sup_state)
        if device_id==0:
            continue
        # If sup slot was passed as a module then overwrite it 
        # such that we can do proper checks for success of 'attach' command
        try:
            index=[dev[0] for dev in device_list].index(device_id)
        except:
            device_list.append((device_id,sup_state))
        else:
            device_list[index]=(device_id,sup_state)

    for device in device_list:
        device_id=int(device[0])
        device_type=device[1]
        logging_level_dict[device_id]={}

        if device_type=='active':
            show_output=hdl.execute(command)
        elif device_type=='standby':
            show_output=hdl.execute(command,'-{0}'.format(device_type))
        else:
            show_output=hdl.execute(command,'-{0} {1}'.format(device_type,device_id))

        if not show_output:
            log.warning('No output in slot {0} for command: {1}'.format(device_id,command))
            continue

        output_list=re.findall('^({0})[ \t]+([0-9]+)[ \t]+([0-9]+)'.format(component),\
            show_output,re.M)
        for component_log_level in output_list:
            facility=component_log_level[0]
            logging_level_dict[device_id][facility]={}
            logging_level_dict[device_id][facility]['Default']=component_log_level[1]
            logging_level_dict[device_id][facility]['Current']=component_log_level[2]

        if not logging_level_dict[device_id]:
            logging_level_dict.pop(device_id,None)

    return logging_level_dict

#======================================================================================#
# getIsisInterfaceBriefDict - Method to get ISIS interface brief output as dictionary
#
# mandatory args:
# hdl - switch handle object from icon
# log - harness/python logging object
#
# optional args:
# vrf - vrf name
# Returned Dictionary Example:
#{'Eth7/1.1': {'interface': 'Eth7/1.1', 'type': 'Bcast', 'idx': '1', 'state': 'Up/Ready', ...'}, ...}
#======================================================================================#
def getIsisInterfaceBriefDict(hdl, log, *args):

    arggrammar = {'vrf': '-type str'}
    ns = parserutils_lib.argsToCommandOptions(args, arggrammar,log, 'namespace')

    sw_cmd = "show isis interface brief"

    if ns.vrf:
        sw_cmd = sw_cmd + " vrf "+ns.vrf

    output = hdl.execute(sw_cmd)
    pat = r'\s*({0})\s+(\w+)\s+(\d+)\s+([\w/]+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/(\d+)\s+(\d+)/(\d+)'.format(rex.INTERFACE_NAME)

    isis_int_list = re.findall(pat, output, flags = re.M)
    isis_int_dict = convertListToDict(isis_int_list,
        ['interface','type','idx','state','circuit','mtu','metric_l1','metric_l2','priority_l1','priority_l2','adj_l1','adj_up_l1','adj_l2','adj_up_l2'],['interface'])

    if not isis_int_list:
         msg = 'No ISIS interfaces found on {0}'.format(hdl.switchName)
         log.info(msg)
         return isis_int_dict
    msg = "isis interface brief dict -{0}".format(isis_int_dict)
    log.info(msg)
    return isis_int_dict

#======================================================================================#
# getIpOspfInterfaceBriefDict - Method to get Ip OSPF interface brief output as dictionary
#
# mandatory args:
# hdl - switch handle object from icon
# log - harness/python logging object
#
# optional args:
# vrf - vrf name
# Returned Dictionary Example:
#{'Vlan29': {'neighbors': '0', 'status': 'up', 'area': '0.0.0.0', 'state': 'DR', 'cost': '40', 'id': '29'}, 'Vlan28': {'neighbors': '0', 'status': 'up', 'area': '0.0.0.0', 'state': 'DR', 'cost': '40', 'id': '28'}, 'Vlan23': {'neighbors': '0', 'status': 'up', 'area': '0.0.0.0', 'state': 'DR', 'cost': '40', 'id': '23'}}
#======================================================================================#
def getIpOspfInterfaceBriefDict(hdl, log, *args):

    arggrammar={}
    arggrammar['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    sw_cmd="show ip ospf interface brief"

    if ns.vrf:
        sw_cmd=sw_cmd+" vrf "+ns.vrf

    output=hdl.execute(sw_cmd)
    pat='[ \t]*({0})[ \t]+([0-9]+)[ \t]+({1})[ \t]+([0-9]+)[ \t]+([a-zA-Z]+)[ \t]+([0-9]+)[ \t]+([a-zA-Z]+)'.format(rex.INTERFACE_NAME,rex.IPv4_ADDR)

    ospf_int_list=re.findall( pat, output, flags=re.M)
    ospf_int_dict=convertListToDict(ospf_int_list,['interface','id','area','cost','state','neighbors','status'],['interface'])

    if len(ospf_int_list)==0:
         msg='No OSPF interfaces found on {0}'.format(hdl.switchName)
         log.info(msg)
         return ospf_int_dict
    msg="ospf interface brief dict -{0}".format(ospf_int_dict)
    log.info(msg)
    return ospf_int_dict

#======================================================================================#
# getIpOspfv3InterfaceBriefDict - Method to get Ipv6 OSPFv3 interface brief output as dictionary
#
# mandatory args:
# hdl - switch handle object from icon
# log - harness/python logging object
#
# optional args:
# vrf - vrf name
# Returned Dictionary Example:
# OrderedDict([('Eth4/11', OrderedDict([('id', '2'), ('area', '0.0.0.0'), ('cost', '4'), \
# ('state', 'DR'), ('neighbors', '1'), ('status', 'up')])), ('Eth3/1', OrderedDict([('id', '1'), \
# ('area', '0.0.0.0'), ('cost', '40'), ('state', 'BDR'), ('neighbors', '1'), ('status', 'up')]))])
#======================================================================================#
def getIpOspfv3InterfaceBriefDict(hdl, log, *args):

    arggrammar={}
    arggrammar['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    sw_cmd="show ipv6 ospfv3 interface brief"

    if ns.vrf:
        sw_cmd=sw_cmd+" vrf "+ns.vrf

    output=hdl.execute(sw_cmd)
    pat='[ \t]*({0})[ \t]+([0-9]+)[ \t]+({1})[ \t]+([0-9]+)[ \t]+([a-zA-Z]+)[ \t]+([0-9]+)[ \t]+([a-zA-Z]+)'.format(rex.INTERFACE_NAME,rex.IPv4_ADDR)

    ospf_int_list=re.findall( pat, output, flags=re.M)
    ospf_int_dict=convertListToDict(ospf_int_list,['interface','id','area','cost','state','neighbors','status'],['interface'])

    if len(ospf_int_list)==0:
         msg='No OSPFv3 interfaces found on {0}'.format(hdl.switchName)
         log.info(msg)
         return ospf_int_dict
    msg="Ospfv3 interface brief dict -{0}".format(ospf_int_dict)
    log.info(msg)
    return ospf_int_dict




def getIpOspfProcessIdList(hdl, log, *args):
    '''
    Returns a list of Ospf process Ids configured on a vrf 
    Mandatory args: hdl, log
    Optional args: vrf
    Sample Usage:
        getIpOspfProcessIdList(hdl, log)
        getIpOspfProcessIdList(hdl, log, '-vrf test')
    '''
    arggrammar={}
    arggrammar['vrf']='-type str -default default'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    sw_cmd= 'show ip ospf vrf {0} | grep "Routing Process"'.format(ns.vrf)
    output=hdl.execute(sw_cmd)
    patstr='Routing Process'
    pat='{0}[ \t]+([0-9]+)[ \t]+[a-z]+'.format(patstr)
    ospf_list=re.findall(pat,output, re.I)
    log.info('Ospf process id on {0} is {1}'.format(hdl.switchName, ospf_list))
    return ospf_list



def getIpOspfInterfaceDetailDict(hdl, log, *args):
    ''' Method to get detailed ospf interface info
    
    Mandatory Args: hdl, log
    Optional Args: vrf, interface
    
    Sample Usage:
    getIpOspfInterfaceDetailDict(hdl, log)
    getIpOspfInterfaceDetailDict(hdl, log, '-interface eth3/1')
    getIpOspfInterfaceDetailDict(hdl, log, '-vrf test')  
    
    Sample rerurned dict:
    Dict[Eth3/1] = OrderedDict([('status', 'up'), ('line_protocol', 'up'), ('IP_addr', '10.10.10.1'), ('mask', '24'), \
    ('Process_ID', '100'), ('VRF', 'default'), ('area', '0.0.0.0'), ('State', 'BDR'), ('Network_type', 'BROADCAST'), \
    ('cost', '40'), ('Index', '2'), ('Transmit_delay', '1'), ('Router_priotity', '1'), ('DR_ID', '1.2.1.3'), ('DR_address', '10.10.10.2'), \
    ('BDR_ID', '1.2.1.2'), ('BDR_address', '10.10.10.1'), ('Neighbors', '1'), ('flooding', '1'), ('adjacencies', '1'), ('Hello_interval', '10'), \
    ('Dead_interval', '40'), ('Wait_timer', '40'), ('Retransmit_interval', '5')])
   
    '''
    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['interface']='-type str'
    arggrammar['mutualExclusive'] =[('vrf','interface')]
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    log.info('Sleeping for 20 sec for Designated Router and backup DR router to form ....')
    time.sleep(20)
   
    sw_cmd='show ip ospf interface'
    if ns.interface:
        sw_cmd=sw_cmd+" "+ns.interface
    elif ns.vrf:
        sw_cmd=sw_cmd+" vrf "+ns.vrf
    
    output=hdl.execute(sw_cmd)
    '''
    pat1="line protocol is"
    pat2="IP address"
    pat3="Process ID"
    pat4="VRF"
    pat5="area"
    pat6="State"
    pat7="Network type"
    pat8="cost"
    pat9="Index"
    pat10="Transmit delay"
    pat11="sec"
    pat12="Router Priority"
    pat13="Designated Router ID:"
    pat14="address:"
    pat15="Backup Designated Router ID:"
    pat16="Neighbors,"
    pat17="flooding to"
    pat18="adjacent with"
    pat19="Timer intervals: Hello"
    pat20="Dead"
    pat21="Wait"
    pat22="Retransmit"
    
    pattern='({0})\s+is\s+([a-zA-z]+),\s+{1}\s+([a-zA-Z]+)\s+{2}\s+({3})\/([0-9]+),\s+{4}\s+({5})\s+{6}\s+\
({7}),\s+{8}\s+({3})\s+.*?{9}\s+([a-zA-Z]+),\s+{10}\s+([a-zA-Z]+),\s+{11}\s+([0-9]+)\s+{12}\s+([0-9]+),\s+{13}\s+\
([0-9]+)\s+{14},\s+{15}\s+([0-9]+)\s+{16}\s+({3}),\s+{17}\s+({3})\s+{18}\s+({3}),\s+{17}\s+({3})\s+([0-9]+)\s+{19}\
\s+{20}\s+([0-9]+),\s+{21}\s+([0-9]+)\s+{22}\s+([0-9]+),\s+{23}\s+([0-9]+),\s+{24}\s+([0-9]+),\s+{25}\s+([0-9]+)'.\
    format(rex.INTERFACE_NAME, pat1, pat2, rex.IPv4_ADDR, pat3, rex.ALPHANUM, pat4, rex.VRF_NAME, pat5, pat6, \
    pat7, pat8, pat9, pat10, pat11, pat12, pat13, pat14, pat15, pat16, pat17, pat18, pat19, pat20, pat21, pat22)
    '''
    eol='[ \t\r\n]+'
    pat1='line protocol is ([a-zA-z]+){0}'.format(eol)
    pat2='(IP address ({0})/([0-9]+){1}|IP address ({0})/([0-9]+), )'.format(rex.IPv4_ADDR,eol)
    pat3='Process ID ([0-9a-zA-Z]+) '
    pat4='VRF ({0}), '.format(rex.VRF_NAME)
    pat5='area ({0}){1}'.format(rex.IPv4_ADDR,eol)
    pat6='State ([a-zA-Z]+), '
    pat7='Network type ([a-zA-Z]+), '
    pat8='cost ([0-9]+){0}'.format(eol)
    pat9='Index ([0-9]+), '
    pat10='Transmit delay ([0-9]+) sec, '
    pat11='Router Priority ([0-9]+){0}'.format(eol)
    pat12='Designated Router ID: ({0}), '.format(rex.IPv4_ADDR)
    pat13='address: ({0}){1}'.format(rex.IPv4_ADDR,eol)
    pat14='Backup Designated Router ID: ({0}), '.format(rex.IPv4_ADDR)
    pat15='address: ({0}){1}'.format(rex.IPv4_ADDR,eol)
    pat16='([0-9]+) Neighbors, '
    pat17='flooding to ([0-9]+), '
    pat18='adjacent with ([0-9]+){0}'.format(eol)
    pat19='Timer intervals: Hello ([0-9]+), '
    pat20='Dead ([0-9]+), '
    pat21='Wait ([0-9]+), '
    pat22='Retransmit ([0-9]+)'
    pat23='Enabled by interface configuration{0}'.format(eol)
     
    pattern='({0}) is ([a-zA-z]+), {1}{2}{3}{4}{5}{23}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}{22}'.\
    format(rex.INTERFACE_NAME, pat1, pat2, pat3, pat4, pat5, pat6, pat7, pat8, pat9, pat10, pat11, pat12, pat13,\
    pat14, pat15, pat16, pat17, pat18, pat19, pat20, pat21, pat22, pat23)

    out=re.findall(pattern, output, re.I|re.DOTALL)
    #for handling white spaces which come for 3500 output
    out=[tuple(filter(None, tp)) for tp in out]
    if (len(out)):
        ospf_int_detail_dict=convertListToDict(out,['interface','status','line_protocol','full_ip_word','IP_addr','mask','Process_ID','VRF', 'area', 'State', \
                               'Network_type', 'cost', 'Index', 'Transmit_delay', 'Router_priotity', 'DR_ID', 'DR_address', \
                               'BDR_ID', 'BDR_address', 'Neighbors', 'flooding', 'adjacencies', 'Hello_interval', 'Dead_interval', \
                               'Wait_timer', 'Retransmit_interval'], 'interface')
    else:
        return {}
    return ospf_int_detail_dict



def getOspfv3InterfaceDetailDict(hdl, log, *args):
    ''' Method to get detailed ospf interface info
    
    Mandatory Args: hdl, log
    Optional Args: vrf, interface
    
    Sample Usage:
    getOspfv3InterfaceDetailDict(hdl, log)
    getOspfv3InterfaceDetailDict(hdl, log, '-interface eth3/1')
    getOspfv3InterfaceDetailDict(hdl, log, '-vrf test')  
    
    Sample rerurned dict:
    Dict[Vlan2] = OrderedDict([('status', 'up'), ('line_protocol', 'up'), ('IPv6_addr', '20::1'), ('mask', '64'), ('Process_ID', '100'), \
    ('VRF', 'default'), ('Instance_ID', '0'), ('area', '0.0.0.0'), ('State', 'BDR'), ('Network_type', 'BROADCAST'), ('cost', '40'), \
    ('Index', '2'), ('Transmit_delay', '1'), ('Router_priotity', '1'), ('DR_ID', '1.2.1.3'), ('DR_address', 'fe80::4255:39ff:fe0d:bf42'), \
    ('BDR_ID', '1.2.1.2'), ('BDR_address', 'fe80::4255:39ff:fe0d:bf41'), ('Neighbors', '1'), ('flooding', '1'), ('adjacencies', '1'), \
    ('Hello_interval', '10'), ('Dead_interval', '40'), ('Wait_timer', '40'), ('Retransmit_interval', '5')])
    '''
    
    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['interface']='-type str'
    arggrammar['mutualExclusive'] =[('vrf','interface')]
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    
    sw_cmd='show ospfv3 interface'
    if ns.interface:
        sw_cmd=sw_cmd+" "+ns.interface
    elif ns.vrf:
        sw_cmd=sw_cmd+" vrf "+ns.vrf
    
    output=hdl.execute(sw_cmd)
    pat1="line protocol is"
    pat2="IPv6 address"
    pat3="Process ID"
    pat4="VRF"
    pat5="area"
    pat6="State"
    pat7="Network type"
    pat8="cost"
    pat9="Index"
    pat10="Transmit delay"
    pat11="sec"
    pat12="Router Priority"
    pat13="Designated Router ID:"
    pat14="address:"
    pat15="Backup Designated Router ID:"
    pat16="Neighbors,"
    pat17="flooding to"
    pat18="adjacent with"
    pat19="Timer intervals: Hello"
    pat20="Dead"
    pat21="Wait"
    pat22="Retransmit"
    pat23="Instance ID"
    
    pattern='({0})\s+is\s+([a-zA-z]+),\s+{1}\s+([a-zA-Z]+)\s+{2}\s+({26})\/([0-9]+)\s+{4}\s+({5})\s+{6}\s+\
({7}),\s+{27}\s+({5}),\s+{8}\s+({3})\s+.*?{9}\s+([a-zA-Z]+),\s+{10}\s+([a-zA-Z]+),\s+{11}\s+([0-9]+)\s+{12}\s+([0-9]+),\s+{13}\s+\
([0-9]+)\s+{14},\s+{15}\s+([0-9]+)\s+{16}\s+({3}),\s+{17}\s+({26})\s+{18}\s+({3}),\s+{17}\s+({26})\s+([0-9]+)\s+{19}\
\s+{20}\s+([0-9]+),\s+{21}\s+([0-9]+)\s+{22}\s+([0-9]+),\s+{23}\s+([0-9]+),\s+{24}\s+([0-9]+),\s+{25}\s+([0-9]+)'.\
    format(rex.INTERFACE_NAME, pat1, pat2, rex.IPv4_ADDR, pat3, rex.ALPHANUM, pat4, rex.VRF_NAME, pat5, pat6,\
           pat7, pat8, pat9, pat10, pat11, pat12, pat13, pat14, pat15, pat16, pat17, pat18, pat19, pat20, pat21, pat22, rex.IPv6_ADDR, pat23)
    
    out=re.findall(pattern, output, re.I|re.DOTALL)
    
    if (len(out)):
        ospfv3_int_detail_dict=convertListToDict(out,['interface','status','line_protocol','IPv6_addr','mask','Process_ID','VRF','Instance_ID', 'area', 'State', \
                               'Network_type', 'cost', 'Index', 'Transmit_delay', 'Router_priotity', 'DR_ID', 'DR_address', \
                               'BDR_ID', 'BDR_address', 'Neighbors', 'flooding', 'adjacencies', 'Hello_interval', 'Dead_interval', \
                               'Wait_timer', 'Retransmit_interval'], 'interface')
    
        return ospfv3_int_detail_dict
    else:
        return {}





def getIpv4BgpNeighborDict(hdl, log, *args):

    # Get the IPv4 BGP neighbor info in dict format
    # Usage: 
    # getIpv4BgpNeighborDict(hdl,log, '-neighbor 10.1.1.2' )
    # getIpv4BgpNeighborDict(hdl,log, '-vrf all' )
    # getIpv4BgpNeighborDict(hdl,log)
    # Sample Output
    # neighbor   remoteport   uptime     localport   type   remotehost   state         routerid   as   holdtime   localhost   keepalive
    # 10.1.1.2   28078        03:26:39   179         ebgp   10.1.1.2     Established   1.1.1.1    2    180        10.1.1.1    60
    # 11.1.1.2   28056        03:26:39   179         ebgp   11.1.1.2     Established   1.1.1.1    2    180        11.1.1.1    60
    # Some values are initialized to default for the cases where neighbor is down

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbor']='-type str'
    cmd = 'show ip bgp neighbors '
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.neighbor:
        cmd = cmd + parse_output.neighbor
    if parse_output.vrf:
        cmd = cmd + 'vrf ' + parse_output.vrf
    #The output can have multiple neighbors, split it
    split_pattern = 'BGP neighbor is'
    pattern1 = 'BGP neighbor is ({0}), +remote AS ({1}), ([a-zA-Z]+) link,'.format(rex.IPv4_ADDR,rex.NUM)
    pattern11 = 'BGP neighbor is ({0}), +remote AS ({1}),\s+local\s+AS\s+({1}),\s+([a-zA-Z]+)\s+link,'.format(rex.IPv4_ADDR,rex.NUM)
    pattern2 = 'remote router ID ({0})'.format(rex.IPv4_ADDR)
    pattern3 = 'BGP state = ([A-Za-z]+), up for ({0})'.format(rex.UPTIME)
    pattern4 = 'hold time = ({0}), keepalive interval is ({1}) seconds'.format(rex.NUM,rex.NUM)
    pattern5 = 'Local host: ({0}), Local port: ({1})'.format(rex.IPv4_ADDR,rex.NUM)
    pattern6 = 'Foreign host: ({0}), Foreign port: ({1})'.format(rex.IPv4_ADDR,rex.NUM)
    pattern7 = 'Peer.*,\s+interface\s+(.*)'
    #get the command output
    cmd_out = hdl.execute(cmd)
    cmd_out_list=cmd_out.split(split_pattern)
    #Initialize the dictionary needed 
    neighbor = {}
    for index in range(1,len(cmd_out_list)):
        cmd_out_list[index] = split_pattern + cmd_out_list[index] 
        match=re.search(pattern1,cmd_out_list[index])
        match11=re.search(pattern11,cmd_out_list[index])
        if match:
            neighbor_ip = match.group(1)
            neighbor[neighbor_ip]={}
            neighbor[neighbor_ip]['as']=match.group(2)
            neighbor[neighbor_ip]['type']=match.group(3)
            #Basic Info present, initialize all other values
            neighbor[neighbor_ip]['routerid']= '0.0.0.0'
            neighbor[neighbor_ip]['state']= 'Idle'
            neighbor[neighbor_ip]['uptime']= '00.00.00'
            neighbor[neighbor_ip]['holdtime']= '0'
            neighbor[neighbor_ip]['keepalive'] = '0'
            neighbor[neighbor_ip]['localhost'] = '0.0.0.0'
            neighbor[neighbor_ip]['localport'] = '0'
            neighbor[neighbor_ip]['remotehost'] = '0.0.0.0'
            neighbor[neighbor_ip]['remoteport'] = '0'
            neighbor[neighbor_ip]['localint'] = ''
        elif match11:
            neighbor_ip = match11.group(1)
            neighbor[neighbor_ip]={}
            neighbor[neighbor_ip]['as']=match11.group(2)
            neighbor[neighbor_ip]['local_as']=match11.group(3)
            neighbor[neighbor_ip]['type']=match11.group(4)
            #Basic Info present, initialize all other values
            neighbor[neighbor_ip]['routerid']= '0.0.0.0'
            neighbor[neighbor_ip]['state']= 'Idle'
            neighbor[neighbor_ip]['uptime']= '00.00.00'
            neighbor[neighbor_ip]['holdtime']= '0'
            neighbor[neighbor_ip]['keepalive'] = '0'
            neighbor[neighbor_ip]['localhost'] = '0.0.0.0'
            neighbor[neighbor_ip]['localport'] = '0'
            neighbor[neighbor_ip]['remotehost'] = '0.0.0.0'
            neighbor[neighbor_ip]['remoteport'] = '0'
            neighbor[neighbor_ip]['localint'] = ''
        else:
            log.error ('Unexpected error, basic neighbor info string does not match')
            continue
        match=re.search(pattern2, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['routerid']=match.group(1)
        else:
            log.error ('Unexpected error')
        match=re.search(pattern3, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['state']=match.group(1)
            neighbor[neighbor_ip]['uptime']=match.group(2)
        match=re.search(pattern4, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['holdtime']=match.group(1)
            neighbor[neighbor_ip]['keepalive']=match.group(2)
        match=re.search(pattern5, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['localhost']=match.group(1)
            neighbor[neighbor_ip]['localport']=match.group(2)
        match=re.search(pattern6, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['remotehost']=match.group(1)
            neighbor[neighbor_ip]['remoteport']=match.group(2)
        match=re.search(pattern7, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['localint']=match.group(1)    
    #return the neighbor dict costruct
    return neighbor

def getIpv6BgpNeighborDict(hdl, log, *args):

    # Get the IPv6 BGP neighbor info in dict format
    # Usage: 
    # getIpv6BgpNeighborDict(hdl,log, '-neighbor 2001::2' )
    # getIpv6BgpNeighborDict(hdl,log, '-vrf all' )
    # getIpv6BgpNeighborDict(hdl,log)
    # Sample Output
    # neighbor   remoteport   uptime     localport   type   remotehost   state         routerid   as   holdtime   localhost   keepalive
    # 2001::2    0      00.00.00   0         ibgp   0.0.0.0     Idle   0.0.0.0    100    180      0.0.0.0    60
    # 2002::2   28056        03:26:39   179  ibgp   2002::2     Established   10.1.1.2    100    180       2002::1    60
    # Some values are initialized to default for the cases where neighbor is down

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['neighbor']='-type str'
    cmd = 'show ipv6 bgp neighbors '
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.neighbor:
        cmd = cmd + parse_output.neighbor
    if parse_output.vrf:
        cmd = cmd + 'vrf ' + parse_output.vrf
    #The output can have multiple neighbors, split it
    split_pattern = 'BGP neighbor is'
    pattern1 = 'BGP neighbor is ({0}), +remote AS ({1}), ([a-zA-Z]+) link,'.format(rex.IPv6_ADDR,rex.NUM)
    pattern14 = 'BGP neighbor is ({0}), +remote AS ({1}), ([a-zA-Z]+) link,'.format(rex.IPv4_ADDR,rex.NUM)
    pattern11 = 'BGP neighbor is ({0}), +remote AS ({1}),\s+local\s+AS\s+({1}),\s+([a-zA-Z]+)\s+link,'.format(rex.IPv6_ADDR,rex.NUM)
    pattern2 = 'remote router ID ({0})'.format(rex.IPv4_ADDR)
    pattern3 = 'BGP state = ([A-Za-z]+), up for ({0})'.format(rex.UPTIME)
    pattern4 = 'hold time = ({0}), keepalive interval is ({1}) seconds'.format(rex.NUM,rex.NUM)
    pattern5 = 'Local host: ({0}), Local port: ({1})'.format(rex.IPv6_ADDR,rex.NUM)
    pattern6 = 'Foreign host: ({0}), Foreign port: ({1})'.format(rex.IPv6_ADDR,rex.NUM)
    #get the command output
    cmd_out = hdl.execute(cmd)
    cmd_out_list=cmd_out.split(split_pattern)
    #Initialize the dictionary needed 
    neighbor = {}
    for index in range(1,len(cmd_out_list)):
        cmd_out_list[index] = split_pattern + cmd_out_list[index]
        match=re.search(pattern1,cmd_out_list[index])
        match14=re.search(pattern14,cmd_out_list[index])
        match11=re.search(pattern11,cmd_out_list[index])
        if match:
            neighbor_ip = match.group(1)
            neighbor[neighbor_ip]={}
            neighbor[neighbor_ip]['as']=match.group(2)
            neighbor[neighbor_ip]['type']=match.group(3)
            #Basic Info present, initialize all other values
            neighbor[neighbor_ip]['routerid']= '0.0.0.0'
            neighbor[neighbor_ip]['state']= 'Idle'
            neighbor[neighbor_ip]['uptime']= '00.00.00'
            neighbor[neighbor_ip]['holdtime']= '0'
            neighbor[neighbor_ip]['keepalive'] = '0'
            neighbor[neighbor_ip]['localhost'] = '0.0.0.0'
            neighbor[neighbor_ip]['localport'] = '0'
            neighbor[neighbor_ip]['remotehost'] = '0.0.0.0'
            neighbor[neighbor_ip]['remoteport'] = '0'
        elif match14:
            neighbor_ip = match14.group(1)
            neighbor[neighbor_ip]={}
            neighbor[neighbor_ip]['as']=match14.group(2)
            neighbor[neighbor_ip]['type']=match14.group(3)
            #Basic Info present, initialize all other values
            neighbor[neighbor_ip]['routerid']= '0.0.0.0'
            neighbor[neighbor_ip]['state']= 'Idle'
            neighbor[neighbor_ip]['uptime']= '00.00.00'
            neighbor[neighbor_ip]['holdtime']= '0'
            neighbor[neighbor_ip]['keepalive'] = '0'
            neighbor[neighbor_ip]['localhost'] = '0.0.0.0'
            neighbor[neighbor_ip]['localport'] = '0'
            neighbor[neighbor_ip]['remotehost'] = '0.0.0.0'
            neighbor[neighbor_ip]['remoteport'] = '0'
        elif match11:
            neighbor_ip = match11.group(1)
            neighbor[neighbor_ip]={}
            neighbor[neighbor_ip]['as']=match11.group(2)
            neighbor[neighbor_ip]['local_as']=match11.group(3)
            neighbor[neighbor_ip]['type']=match11.group(4)
            #Basic Info present, initialize all other values
            neighbor[neighbor_ip]['routerid']= '0.0.0.0'
            neighbor[neighbor_ip]['state']= 'Idle'
            neighbor[neighbor_ip]['uptime']= '00.00.00'
            neighbor[neighbor_ip]['holdtime']= '0'
            neighbor[neighbor_ip]['keepalive'] = '0'
            neighbor[neighbor_ip]['localhost'] = '0.0.0.0'
            neighbor[neighbor_ip]['localport'] = '0'
            neighbor[neighbor_ip]['remotehost'] = '0.0.0.0'
            neighbor[neighbor_ip]['remoteport'] = '0'
        else:
            log.error ('Unexpected error, basic neighbor info string does not match')
            continue
        match=re.search(pattern2, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['routerid']=match.group(1)
        else:
            log.error ('Unexpected error')
        match=re.search(pattern3, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['state']=match.group(1)
            neighbor[neighbor_ip]['uptime']=match.group(2)
        match=re.search(pattern4, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['holdtime']=match.group(1)
            neighbor[neighbor_ip]['keepalive']=match.group(2)
        match=re.search(pattern5, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['localhost']=match.group(1)
            neighbor[neighbor_ip]['localport']=match.group(2)
        match=re.search(pattern6, cmd_out_list[index])
        if match:
            neighbor[neighbor_ip]['remotehost']=match.group(1)
            neighbor[neighbor_ip]['remoteport']=match.group(2)
    #return the neighbor dict costruct
    return neighbor

def getIpv4BgpSummaryDict(hdl, log, *args):

    # Get the IPv4 BGP neighbor summary in dictionary format
    # Usage:0
    # getIpv4BgpSummaryDict(hdl,log, '-vrf all' )
    # getIpv4BgpSummaryDict(hdl,log)


    # Sample Output
    # neighbor   outQ   statePfx   ver   msgsent   inQ   updowntime   as   msgrcvd   tblver
    # 10.1.1.2   0      Idle       4     1491      0     01:20:41     2    1481      0
    # 11.1.1.2   0      0          4     1571      0     04:47:45     2    1564      22

    arggrammar={}
    arggrammar['vrf']='-type str'
    cmd = 'show ip bgp summary '
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.vrf:
        cmd = cmd + 'vrf ' + parse_output.vrf
    #The output can have multiple neighbors, split it
    pattern = '({0}) +({1}) +({1}) +({1}) +({1}) +({1}) +({1}) +({1}) +({2}) +([A-Za-z0-9]+)'.format(\
        rex.IPv4_ADDR,rex.NUM,rex.UPTIME)
    #get the command output
    cmd_out = hdl.execute(cmd)
    bgp_matchlist = re.findall(pattern,cmd_out)
    return convertListToDict(bgp_matchlist,['neighbor','ver','as','msgrcvd','msgsent','tblver','inQ','outQ','updowntime','statePfx'],['neighbor'])

def getIpv6BgpSummaryDict(hdl, log, *args):
 
    # Get the IPv6 BGP neighbor summary in dictionary format
    # Usage:0
    # getIpv6BgpSummaryDict(hdl,log, '-vrf all' )
    # getIpv6BgpSummaryDict(hdl,log)
 
 
    # Sample Output
    # neighbor   outQ   statePfx   ver   msgsent   inQ   updowntime   as   msgrcvd   tblver
    # 1011::2   0      Idle       4     1491      0     01:20:41     2    1481      0
    # 1111::2   0      0          4     1571      0     04:47:45     2    1564      22
 
    arggrammar={}
    arggrammar['vrf']='-type str'
    cmd = 'show ip bgp summary '
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.vrf:
        cmd = cmd + 'vrf ' + parse_output.vrf
    #The output can have multiple neighbors, split it
    pattern = '({0}) +({1}) +({1}) +({1}) +({1}) +({1}) +({1}) +({1}) +({2}) +([A-Za-z0-9]+)'.format(\
        rex.IPv6_ADDR,rex.NUM,rex.UPTIME)
    #get the command output
    cmd_out = hdl.execute(cmd)
    bgp_matchlist = re.findall(pattern,cmd_out)
    return convertListToDict(bgp_matchlist,['neighbor','ver','as','msgrcvd','msgsent','tblver','inQ','outQ','updowntime','statePfx'],['neighbor'])

### VxLAN get methods ###
def getNveVniDict(hdl,log):
        """ Added by sandesub """
        output=hdl.execute("show nve vni")
        pattern="("+rex.ALPHANUM+")"        
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.IPv4_ADDR+")"
        pattern=pattern+"[ \t]+("+rex.ALPHA+")"
        nve_vni_list=re.findall(pattern,output,flags=re.M)
        nve_vni_dict=convertListToDict(nve_vni_list,['Interface','VNI','Multicast_Group','VNI_State'],['VNI'])
        return nve_vni_dict

def getNvePeersDict(hdl,log):
        """ Added by sandesub """
        output=hdl.execute("show nve peers")
        pattern="("+rex.ALPHANUM+")"        
        pattern=pattern+"[ \t]+("+rex.IPv4_ADDR+")"
        pattern=pattern+"[ \t]+("+rex.ALPHA+")"        
        #comment off VNI match
        #pattern=pattern+"[ \t]+("+rex.NUM+")"
        nve_peer_list=re.findall(pattern,output,flags=re.M)
        nve_peer_dict=convertListToDict(nve_peer_list,['Interface','Peer_IP','Peer_State'],['Peer_IP'])
        return nve_peer_dict


def getNveStatsDict(hdl,log,*args):
        """ Added by sandesub """
        arggrammar={}
        arggrammar['intf']='-type str -required True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
        intf=ns.intf
        output=hdl.execute('show int {0} | grep -A 2 RX'.format(intf))
        pattern="("+rex.NUM+")[ \t]+unicast[ \t]+packets[ \t]+("+rex.NUM+")[ \t]+multicast[ \t]+packets"
        rx_pkts_list = re.findall(pattern,output,flags=re.M)
        if rx_pkts_list:
            item = rx_pkts_list[0]
            t = ()
            t = t + ('RX',)
            t = t + item
            rx = []
            rx.append(t)
        else:
            rx = []
        pkt_dict=convertListToDict(rx,['RX','Unicast','Multicast'],['RX'])

        output=hdl.execute('show int {0} | grep -A 2 TX'.format(intf))
        pattern="("+rex.NUM+")[ \t]+unicast[ \t]+packets[ \t]+("+rex.NUM+")[ \t]+multicast[ \t]+packets"
        tx_pkts_list = re.findall(pattern,output,flags=re.M)
        if tx_pkts_list:
            item = tx_pkts_list[0]
            t = ()
            t = t + ('TX',)
            t = t + item
            tx = []
            tx.append(t)
        else:
            tx = []
        tx_pkt_dict=convertListToDict(tx,['TX','Unicast','Multicast'],['TX'])
        pkt_dict.update(tx_pkt_dict)
        return pkt_dict

def getNveStatsDict(hdl,log,*args):
        """ Added by sandesub """
        arggrammar={}
        arggrammar['intf']='-type str -required True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
        intf=ns.intf
        output=hdl.execute('show int {0} | grep -A 2 RX'.format(intf))

def getACLEntriesCount(hdl,log):
        """ Added by sandesub"""
        output=hdl.execute("show ip access-lists summary | grep ACEs")
        count=0
        pattern="Total ACEs Configured:"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        ace_list=re.findall(pattern,output,flags=re.M)
        for ace in ace_list:
                count = count + int(ace)
        return count
 
### VxLAN block ends here ###        

def getNtpPeerDict(hdl,log):
        """Added by sandesub"""
        # Returns ntp peer dictionary
        # NTP server IP is first level key 
        output = hdl.execute("show ntp peers")
        pattern="("+rex.IPv4_ADDR+")"        
        pattern=pattern+"[ \t]+("+rex.ALPHANUM+")"
        ntp_peer_list=re.findall(pattern,output,flags=re.M)
        ntp_peer_dict=convertListToDict(ntp_peer_list,['Peer_IP_Address','Server'],['Peer_IP_Address'])
        log.info("NTP Peers Dict: " + str(ntp_peer_dict))
        return ntp_peer_dict

# Added by sandesub
def getNtpPeerList(hdl,log):
        # Returns ntp peer list
        ntp_peer_dict = getNtpPeerDict(hdl,log)
        ntp_peer_list = ntp_peer_dict.keys()
        log.info("NTP Peers List: " + str(ntp_peer_list))
        return ntp_peer_list 

# Added by sandesub
def getEnvPowerRedundancyMode(hdl,log):
        # Returns the operational PS redundancy mode 
        output = hdl.execute("show environment power")
        pattern = "Power Supply redundancy mode \(operational\)[ \t]+("+rex.ALPHANUMSPECIAL+")" 
        mode = re.findall(pattern,output)
        log.info("Power supply redundancy mode: " + str(mode))
        return mode

# Added by sandesub
def getEnvPowerStatusDict(hdl,log,mod):
        # Returns the details of power-supply module
        output = hdl.execute("show environment power | head lines 10")
        pattern = "({0})".format(mod)        
        pattern=pattern+"[ \t]+("+rex.ALPHANUMSPECIAL+")"
        pattern=pattern+"[ \t]+("+rex.NUM+"\s+W)"
        pattern=pattern+"[ \t]+("+rex.NUM+"\s+W)"
        pattern=pattern+"[ \t]+("+rex.ALPHA+")"
        module_info = re.findall(pattern,output)
        log.info("Module Info List: " + str(module_info))
        module_info_dict = convertListToDict(module_info,['Power_Supply','Model','Actual_Output','Total_Capacity','Status'],['Power_Supply'])
        log.info("Module Info Dict: " + str(module_info_dict))
        return module_info

# Added by sandesub
def getIpv6NeighborDict(hdl,log,vrf):
        # Returns dict of IPv6 neighbors on a given VRF
        output = hdl.execute("show ipv6 neighbor vrf {0}".format(vrf))
        pattern="("+rex.IPv6_ADDR+")"        
        pattern=pattern+"[ \t]+("+rex.CLOCK_TIME+")"
        pattern=pattern+"[ \t]+("+rex.MACADDR+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.ALPHANUM+")"
        pattern=pattern+"[ \t]+("+rex.INTERFACE_NAME+")"
        nbr_list = re.findall(pattern,output)
        ### convert the IPv6 prefix to exploded format - swanaray
        for i in range(len(nbr_list)):
            tmp=list(nbr_list[i])
            tmp[0]=ipaddr.IPv6Address(tmp[0]).exploded
            nbr_list[i]=tuple(tmp)
        log.info("IPv6 Neighbor List: " + str(nbr_list))
        nbr_dict = convertListToDict(nbr_list,['Address','Age','MAC_Address','Pref','Source','Interface'],['Address'])
        log.info("IPv6 Neighbor Dict: " + str(nbr_dict))
        return nbr_dict

def getIpv6NeighborDetailDict (hdl,log, *args):
    """
    anandksi(03/25/2014)
    This is made identical to ip arp detail even though Nx-OS command op is different
    Return IPv6 neighbor details for a given (or all) physical interfaces in a dictionary format.
    If an specific physical interface is not passed all entries are captured including
    where interface name is '-'.
    In case of vPC ND sync feature it can be used to verify ND sync for vPCs.
    intf can be single Physical interface or list of interfaces
    Sample Usage:
    getIpv6NeighborDetailDict(hdl,log)
    getIpv6NeighborDetailDict(hdl,log,'-vrf vrf_name')
    interface can be one interface or list
    getIpv6NeighborDetailDict(hdl,log,'-int intf')
    """

    arggrammar={}
    arggrammar['intf']='-type str'
    arggrammar['vrf']='-type str'
    argparse=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    intfList=[]
    if argparse.intf:
        intfList = strToList(getFullInterfaceName(log,argparse.intf))

    if (argparse.vrf):
        cmd_out = hdl.execute('show ipv6 neighbor detail vrf {0}'.format(argparse.vrf))
    else:
        cmd_out = hdl.execute ('show ipv6 neighbor detail')
    #The output can have multiple neighbors, split on each IPv6 Address
    split_pattern = 'Address :'
    pattern1 = 'Address :\s+({0})'.format(rex.IPv6_ADDR)
    pattern2 = 'Age :\s+({0})'.format(rex.UPTIME)
    pattern3 = 'MacAddr :\s+({0})'.format(rex.MACADDR)
    pattern4 = 'Interface :\s+({0}\-)'.format(rex.INTERFACE_NAME)
    pattern5 = 'Physical Interface :\s+({0}|\-)'.format(rex.INTERFACE_NAME)
    cmd_out_list=cmd_out.split(split_pattern)
    #Initialize the dictionary needed 
    nd_dict = {}
    for index in range(1,len(cmd_out_list)):
        cmd_out_list[index] = split_pattern + cmd_out_list[index] 
        if intfList:
            # is this entry of the interest
            match=re.search(pattern5,cmd_out_list[index])
            if match:
                phy_int=getFullInterfaceName(log,match.group(1))
                if phy_int in intfList:
                    match=re.search(pattern1,cmd_out_list[index])
                    if match:
                        neighbor_ip=match.group(1)
                        nd_dict[neighbor_ip]={}
                        nd_dict[neighbor_ip]['Physical_Interface']=phy_int
                    match=re.search(pattern2,cmd_out_list[index])
                    if match:
                        nd_dict[neighbor_ip]['Age']=match.group(1)
                    match=re.search(pattern3,cmd_out_list[index])
                    if match:
                        nd_dict[neighbor_ip]['Mac_Address']=match.group(1)
                    match=re.search(pattern4,cmd_out_list[index])
                    if match:
                        nd_dict[neighbor_ip]['Interface']=match.group(1)

        else:
            match=re.search(pattern5,cmd_out_list[index])
            if match:
                phy_int=getFullInterfaceName(log,match.group(1))
                match=re.search(pattern1,cmd_out_list[index])
                if match:
                    neighbor_ip=match.group(1)
                    nd_dict[neighbor_ip]={}
                    nd_dict[neighbor_ip]['Physical_Interface']=phy_int
                match=re.search(pattern2,cmd_out_list[index])
                if match:
                    nd_dict[neighbor_ip]['Age']=match.group(1)
                match=re.search(pattern3,cmd_out_list[index])
                if match:
                    nd_dict[neighbor_ip]['Mac_Address']=match.group(1)
                match=re.search(pattern4,cmd_out_list[index])
                if match:
                    nd_dict[neighbor_ip]['Interface']=match.group(1)
    #return the neighbor dict costruct
    return nd_dict



# Added by sandesub
def getIpv6NeighborList(hdl,log,vrf):
        # Returns list of IPv6 neighbors for a given VRF
        nbr_dict = getIpv6NeighborDict(hdl,log,vrf)
        nbr_list = nbr_dict.keys()
        log.info("IPv6 Neighbors List: " + str(nbr_list))
        return nbr_list

def getTcamRegionSize(hdl,log,*args):
    """ 
    Added by sandesub
    Returns the TCAM size for a given region
    """
    arggrammar={}
    arggrammar['region']='-type str -required True -choices ["VPC-Convergence","IPV4-PACL","IPV6-PACL","MAC-PACL","IPV4-Port-QoS","IPV6-Port-QoS","MAC-Port-QoS","FEX-IPV4-PACL","FEX-IPV6-PACL","FEX-MAC-PACL","FEX-IPV4-Port-QoS","FEX-IPV6-Port-QoS","FEX-MAC-Port","IPV4-VACL","IPV6-VACL","MAC-VACL","IPV4-VLAN-QoS","IPV6-VLAN-QoS","MAC-VLAN-QoS","IPV4-RACL","IPV6-RACL","MAC-RACL","Egress-IPV4-PACL","Egress-IPV6-PACL","Egress-MAC-PACL","FEX-Egress-IPV4-PACL","FEX-Egress-IPV6-PACL","FEX-Egress-MAC-PACL","Egress-IPV4-VACL","Egress-IPV6-VACL","Egress-IPV4-RACL","Egress-IPV6-RACL","Egress-MAC-RACL","IPV4-L3-QoS","IPV6-L3-QoS","MAC-L3-QoS","Ingress-System","Egress-System","SPAN","Ingress-SVI-Counters","Redirect"]'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    region_dict = getTcamRegionDict(hdl,log)
    size=region_dict[ns.region] 
    return size

def getRegionTableName(hdl,log,*args):
    """ 
    Added by sandesub
    Returns the region table name given the region CLI name
    """
    arggrammar={}
    arggrammar['cli_region_name']='-type str -required True -choices ["vpc-convergence","span","redirect","svi","mac-ifacl","mac-vacl","e-ipv6-racl","e-racl","fex-ifacl","fex-ipv6-ifacl","fex-mac-ifacl","ifacl","ipv6-ifacl","ipv6-racl","ipv6-vacl","racl","vacl","qos","vqos","l3qos"]'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    region_dict={}
    region_dict.update({'svi':'Ingress-SVI-Counters'})
    region_dict.update({'redirect':'Redirect'})
    region_dict.update({'span':'SPAN'})
    region_dict.update({'vpc-convergence':'VPC-Convergence'})
    region_dict.update({'mac-ifacl':'MAC-PACL'})
    region_dict.update({'mac-vacl':'MAC-VACL'})
    region_dict.update({'e-ipv6-racl':'Egress-IPV6-RACL'})
    region_dict.update({'e-racl':'Egress-IPV4-RACL'})
    region_dict.update({'fex-ifacl':'FEX-IPV4-PACL'})
    region_dict.update({'fex-ipv6-ifacl':'FEX-IPV6-PACL'})
    region_dict.update({'fex-mac-ifacl':'FEX-MAC-PACL'})
    region_dict.update({'ifacl':'IPV4-PACL'})
    region_dict.update({'ipv6-ifacl':'IPV6-PACL'})
    region_dict.update({'ipv6-racl':'IPV6-RACL'})
    region_dict.update({'ipv6-vacl':'IPV6-VACL'})
    region_dict.update({'racl':'IPV4-RACL'})
    region_dict.update({'vacl':'IPV4-VACL'})
    region_dict.update({'qos':'IPV4-Port-QoS'})
    region_dict.update({'vqos':'IPV4-VLAN-QoS'})
    region_dict.update({'l3qos':'IPV4-L3-QoS'})
    region_table_name = region_dict[ns.cli_region_name]    
    return region_table_name

def getTcamRegionDict(hdl,log,*args):
    arggrammar={}
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    #returns the size of a given region
    output = hdl.execute("show hardware access-list tcam region")
    pattern="([0-9a-zA-Z\ ]+)"
    #pattern=pattern+"[ \t]+size ="
    pattern=pattern+".*?size ="
    pattern=pattern+"[ \t]+("+rex.NUM+")"
    region_list = re.findall(pattern,output)
    new_region_list = []
    size_list = []
    for (region,size) in region_list:
        #new_region = region.lstrip()
        new_region = region.strip()
        new_region=new_region.replace(' ','-')
        new_region_list.append(new_region)
        size_list.append(size)
    reg = zip(new_region_list,size_list)
    region_dict=convertListToDict(reg,['Region_Name','Size'],['Region_Name'])
    return region_dict

def getResultRaclCC(hdl,log,*args):
    arggrammar={}
    arggrammar['module']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    cmd="show consistency-checker racl module " +ns.module
    output=hdl.execute(cmd,timeout=180)
    pattern1="Consistency Check:"
    pattern2=""
    pattern1=pattern1+"[ \t]+("+rex.ALPHA+")"
    pattern2=pattern2+"[ \t]+("+rex.INTERFACE_NAME+")+[ \t]\(("+rex.ALPHA+")\)"
    list1 = re.findall(pattern1,output,re.M)
    list2 = re.findall(pattern2,output,re.M)
    list3 = list1 + list2
    print (list1)
    print (list2)
    print (list3)
    return (list3)

#======================================================================================#
# getIpOspfRouteSummaryDict - Method to get Ip Ospf Route Summary
#
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#
# optional args
# vrf - vrf name to get Ip route count in non-default vrf 
#
#Returned Dictionary Example - {'discard-internal': {'routes': '0', 'paths': '0'}, 'nssa_type-1': {'routes': '0', 'paths': '0'}, 'nssa_type-2': {'routes': '0', 'paths': '0'}, 'type-2': {'routes': '0', 'paths': '0'}, 'Total_number_of_paths': '45', 'Total_number_of_routes': '45', 'discard-external': {'routes': '0', 'paths': '0'}, 'nopath': {'routes': '0', 'paths': '0'}, 'type-1': {'routes': '0', 'paths': '0'}, 'inter': {'routes': '0', 'paths': '0'}, 'intra': {'routes': '45', 'paths': '45'}}
#======================================================================================#
def getIpOspfRouteSummaryDict(hdl, log, *args):
    arggrammar={}
    arggrammar['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    sw_cmd="show ip ospf route summary"

    if ns.vrf:
        sw_cmd=sw_cmd+" vrf "+ns.vrf

    output=hdl.execute(sw_cmd)
    tot_routes_pat='Total number of routes:[ \t]*([0-9]+)'
    tot_paths_pat='Total number of paths:[ \t]*([0-9]+)'

    if re.findall( tot_routes_pat, output, flags=re.M)==[]:
        msg='Ospf process is not running'
        log.info(msg)
        return {}

    total_routes=re.findall( tot_routes_pat, output, flags=re.M)[0]
    total_paths=re.findall( tot_paths_pat, output, flags=re.M)[0]

    pat='^([^ ]+(?: [^ ]+)?)[ \t]*\:+[ \t]+\(+[ \t]+([0-9]+)[ \t]*,[ \t]+([0-9]+)[ \t]*\)'
    ospf_route_summary_list=re.findall( pat, output, flags=re.M)
    ospf_route_summary_dict=convertListToDict(ospf_route_summary_list,['type','routes','paths'],['type'])

    # Replace spaces in keys with underscore
    for type in ospf_route_summary_dict.keys():
        ospf_route_summary_dict[re.sub(' ','_',type)] = ospf_route_summary_dict.pop(type)

    ospf_route_summary_dict.update({'Total_number_of_routes':total_routes})
    ospf_route_summary_dict.update({'Total_number_of_paths':total_paths })

    return ospf_route_summary_dict

#======================================================================================#
#
# getInterfaceStatusDict- Method to get list of interfaces and its status (show interface status <sub-cmd>)
#
# == mandatory args ==
# hdl - switch handle object from icon
# log - harness/python logging object
#
# == optional args ==
# sub cmd - interface status type option being up/down/err-disabled/err-vlans/inactive/module
#
# == Caller format example ==
# eor_utils.getInterfaceStatusDict(hdl,log,'-err-disabled')
# eor_utils.getInterfaceStatusDict(hdl,log,'-err-vlans')
# eor_utils.getInterfaceStatusDict(hdl,log,'-up')
# eor_utils.getInterfaceStatusDict(hdl,log,'-down')
#
# == Returns Interface dictionary ==
# first level key - interface/port itself as first level key
# second level keys -Name,Status,Vlan,Duplex,Speed,Type for sub-cmd options up/down/inactive/module
# second level keys -Name,Status,Reason for sub-cmd option err-disabled interfaces
# second level keys -Name,Err-vlans,Status for sub-cmd option err-vlans interfaces
#
# == Returned Dictionary Example == 
# Err disabled Interface Dictionary :{'Eth101/1/3': {'Status': 'bpdugrdErrDis', 'Reason': 'BPDUGuard errDisable', 'Name': '--'}, 'Eth101/1/4': {'Status': 'bpdugrdErrDis', 'Reason': 'BPDUGuard errDisable', 'Name': '--'}}
# Errored-vlans Interface Dictionary :{}
# Interface Dictionary {'Eth3/3': {'Status': 'connected', 'Name': '--', 'Duplex': 'full', 'Speed': '1000', 'Vlan': 'routed', 'Type': '1000base-T'}, 'Eth3/2': {'Status': 'connected', 'Name': '--', 'Duplex': 'full', 'Speed': '1000', 'Vlan': 'routed', 'Type': '1000base-T'}}
#
#======================================================================================#

def getInterfaceStatusDict(hdl, log, *args):
    arggrammar={}
    arggrammar['down']='-type bool'
    arggrammar['up']='-type bool'
    arggrammar['inactive']='-type bool'
    arggrammar['err-disabled']='-type bool'
    arggrammar['err-vlans']='-type bool'
    arggrammar['module']='-type int'
    arggrammar['interface']='-type str -format {0}'.format(rex.INTERFACE_RANGE)
    arggrammar['mutualExclusive'] =[('down','up','inactive','err-disabled','err-vlans','module')]

    argnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if not argnamespace.VALIDARGS:
        log.warning('Invalid arguments')
        return {}

    if argnamespace.interface:
        interfaces=argnamespace.interface
        command="show interface {0} status ".format(interfaces) + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str",['interface'])
        search=re.search('(?:int|int[erface]+) ((?:{0}| +)+)'.format(rex.INTERFACE_RANGE),command,re.I)
        if search and re.search(',',search.group(1)):
            # Split non-homogeneous ranges and get cumulative output
            intf_list=re.split('[, ]+',search.group(1))
            intf_list=filter(None, intf_list)
            intf_dict={}
            intf_dict['fex_intf']=[intf for intf in intf_list \
                if re.search('eth[ernet]*[0-9]+/[0-9]+/[0-9]+',intf,re.I)]
            intf_dict['switch_intf']=[intf for intf in intf_list \
                if re.search('eth[ernet]*[0-9]+/[0-9]+(?!(/[0-9]+|\.[0-9]+))',intf,re.I)]
            intf_dict['switch_sub_intf']=[intf for intf in intf_list \
                if re.search('eth[ernet]*[0-9]+/[0-9]+\.[0-9]+',intf,re.I)]
            intf_dict['po_intf']=[intf for intf in intf_list \
                if re.search('po[rtchannel-]*[0-9]+',intf,re.I)]
            intf_dict['svi_intf']=[intf for intf in intf_list \
                if re.search('vlan[0-9]+',intf,re.I)]
            intf_dict['lo_intf']=[intf for intf in intf_list \
                if re.search('lo[opback]*[0-9]+',intf,re.I)]
            if len(intf_list) != len(intf_dict['switch_intf'])+len(intf_dict['switch_sub_intf'])+len(intf_dict['fex_intf'])+\
                len(intf_dict['po_intf'])+len(intf_dict['svi_intf'])+len(intf_dict['lo_intf']):
                testResult('fail','Could not identify one of the interface types',log)
                return ''
            showoutput=''
            for intf_type in intf_dict:
                if intf_dict[intf_type]:
                    intf_range=','.join(intf_dict[intf_type])
                    new_cmd=re.sub('(?:int|int[erface]+) (?:{0}| +)+'.format(rex.INTERFACE_RANGE),'int {0} '.format(intf_range),command,re.I)
                    showoutput+=hdl.execute(new_cmd)
        else:
            showoutput=hdl.execute(command)
    else:
        command="show interface status " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
        showoutput=hdl.execute(command)

    intdict={}
    if 'err-disabled' in argnamespace.KEYS:
        interfacelist=re.findall(\
         "^([Mgmt0-9]+|[Eth0-9/]+|Vlan[0-9]+|Po[0-9]+|lo[opback]*[0-9]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^\t\r\n]+)[\t\r\n]+", showoutput, re.M | re.I)
        #intdict=convertListToDict(interfacelist,['Port','Name','Status','Reason'],'Port')
        if len(interfacelist):
            for interface in interfacelist:
                intf=normalizeInterfaceName(log,interface[0])
                intdict[intf] = {}
                intdict[intf]['Name'] = interface[1]
                intdict[intf]['Status'] = interface[2]
                intdict[intf]['Reason'] = interface[3]

        log.debug("Err disabled Interface Dictionary :" + str(intdict))
        return intdict
    if 'err-vlans' in argnamespace.KEYS:
        interfacelist=re.findall(\
         "^([Mgmt0-9]+|[Eth0-9/]+|Vlan[0-9]+|Po[0-9]+|lo[opback]*[0-9]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^\t\r\n]+)[\t\r\n]+", showoutput, re.M | re.I)
        #intdict=convertListToDict(interfacelist,['Port','Name','Err-Vlans','Status'],'Port')
        if len(interfacelist):
            for interface in interfacelist:
                intf=normalizeInterfaceName(log,interface[0])
                intdict[intf] = {}
                intdict[intf]['Name'] = interface[1]
                intdict[intf]['Err-Vlans'] = interface[2]
                intdict[intf]['Status'] = interface[3]

        log.debug("Errored-vlans Interface Dictionary :" + str(intdict))
        return intdict
    else:
        interfacelist=re.findall(\
         "^([Mgmt0-9]+|[Eth0-9/]+|Vlan[0-9]+|Po[0-9]+|lo[opback]*[0-9]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^ \t]+)[ \t]+([^ \t\r\n]+)[ \t\r\n]+",
         showoutput, re.M | re.I)
    
        #intdict=convertListToDict(interfacelist,['Port','Name','Status','Vlan','Duplex','Speed','Type'],'Port')
        if len(interfacelist):
            for interface in interfacelist:
                intf=normalizeInterfaceName(log,interface[0])
                intdict[intf] = {}
                intdict[intf]['Name'] = interface[1]
                intdict[intf]['Status'] = interface[2]
                intdict[intf]['Vlan'] = interface[3]
                intdict[intf]['Duplex'] = interface[4]
                intdict[intf]['Speed'] = interface[5]
                intdict[intf]['Type'] = interface[6]


        log.debug(str(argnamespace.KEYS) + " Interface Dictionary " + str(intdict))
        return intdict


# Function to return unique elements in a list
# For e.g if list has [1,2,1,3,1,5], this will return
# [1,2,3,5]
def uniqueList(inputlist):

    returnlist=[]
    for elem in inputlist:
        if not elem in returnlist:
            returnlist.append(elem)

    return returnlist

# To be depreceated, use strTolist instead
# Usages strtolist('1,2,3')
#        strtolist('1 2 3')
#        strtolist('1, 2, 3')
# All three will return list of ['1',2,'3']
def strtolist(inputstr,retainint=False):
     inputstr=str(inputstr)
     inputstr=inputstr.strip("[]")
     splitbycomma=inputstr.split(",")
     splitbyspace=inputstr.split()
     if len(splitbycomma) >= 2:
         returnlist=[]
         for elem in splitbycomma:
             elem=elem.strip(" '")
             elem=elem.strip('"')
             if elem.isdigit() and retainint:
                 returnlist.append(int(elem))
             else:
                 returnlist.append(elem)
         return returnlist
     returnlist=[]
     for elem in splitbyspace:
         elem=elem.strip(" '")
         elem=elem.strip('"')
         if elem.isdigit() and retainint:
             returnlist.append(int(elem))
         else:
             returnlist.append(elem)
     return returnlist

# Add camelcased name to strTolist. Use this one instead
# of strtolist moving forward. For the sake of  consistency
# we will depreciate strtolist (and convert existing references
# to strToList)

def strToList(inputstr,retainint=False):
    return strtolist(inputstr,retainint)

# To be depreceated, use strToExpandedlist instead
# Usages strtoexpandedlist('1-5,10,12-15')
# Will return list of ['1','2','3','4','5','10','12',13',14','15']
# strtoexpandedlist('eth1/1-eth1/3,eth1/11,eth2/15-16,eth3/1/2-4,eth3/2/6,eth4/1/7-eth4/1/9,po2-po4') will return
# ['eth1/1', 'eth1/2', 'eth1/3', 'eth1/11', 'eth2/15', 'eth2/16', 'eth3/1/2', 'eth3/1/3', 'eth3/1/4', 'eth3/2/6', 'eth4/1/7', 'eth4/1/8', 'eth4/1/9', 'po2', 'po3', 'po4']

def strtoexpandedlist(inputstr,retainint=False):
    returnlist=[]
    for elem in strtolist(inputstr,retainint):
       if not elem:
           continue
       if re.search('str',str(type(elem))):
           subelem=elem.split("-")
       else:
           subelem=str(elem).split("-")
       prefix1=""
       if len(subelem) == 2:
           intlist1=re.findall("("+rex.INTERFACE_TYPE+")("+rex.INTERFACE_NUMBER+")",subelem[0])
           if len(intlist1):
               prefix1=intlist1[0][0]
               moduleport=intlist1[0][1].split("/")
               if len(moduleport) == 1:
                  port1=moduleport[0]
               else:
                  port1=moduleport[len(moduleport)-1]
                  for i in range(len(moduleport)-1):
                      prefix1=prefix1+moduleport[i]+"/"

               modulesubport=port1.split(".")
               if len(modulesubport) == 1:
                  port1=modulesubport[0]
               else:
                  port1=modulesubport[len(modulesubport)-1]
                  for i in range(len(modulesubport)-1):
                      prefix1=prefix1+modulesubport[i]+"."
           else:
                port1=subelem[0]

           intlist=re.findall("("+rex.INTERFACE_TYPE+")("+rex.INTERFACE_NUMBER+")",subelem[1])
           if len(intlist):
               prefix2=intlist[0][0]
               moduleport=intlist[0][1].split("/")
               if len(moduleport) == 1:
                  port2=moduleport[0]
               else:
                  port2=moduleport[len(moduleport)-1]
                  for i in range(len(moduleport)-1):
                      prefix2=prefix2+moduleport[i]+"/"

               modulesubport=port2.split(".")
               if len(modulesubport) == 1:
                  port2=modulesubport[0]
               else:
                  port2=modulesubport[len(modulesubport)-1]
                  for i in range(len(modulesubport)-1):
                      prefix2=prefix2+modulesubport[i]+"."

               if prefix1 != prefix2:
                   print ('Mismatched port types in range {0}'.format(elem))
                   return '' 
           else:
                port2=subelem[1]

           if (type(port1) is str and not port1.isdigit()) or (type(port2) is str and not port2.isdigit()):
               returnlist.append(elem)
               continue 


           for i in range(int(port1),int(port2)+1):
               if prefix1 == "":
                   if retainint:
                       returnlist.append(i)
                   else:
                       returnlist.append(str(i))
               else:
                   returnlist.append(prefix1+str(i))
       else:
           if 'isdigit' in dir(elem) and elem.isdigit() and retainint:
               returnlist.append(int(elem))
           else:
               returnlist.append(elem)
    return returnlist


# Add camelcased name to strTolist. Use this one instead
# of strtoexpandedlist moving forward. For the sake of  consistency
# we will depreciate strtoexpandedlist (and convert existing references
# to strToExpandedList)

def strToExpandedList(inputstr,retainint=False):
    return strtoexpandedlist(inputstr,retainint)

#Usages:
#listtostr([1,2,3])
#listtostr([(1,2),(3,4)])
def listtostr(inputlist):
    ret_str=''
    for char in inputlist:
        ret_str+=str(char)+','
    return ret_str.strip(',')


#Function to find an input dictionary expected by user in an output dictionry from CLI output 
#All keys in input dict should be available in output dict
#The values of each key in input dict should be the same as output dict
#By default, it assumes a one-level dictionary
#it accepts 2-level dictionary as an option
def findDict(log,inputDict,outputDict,depth=1):
    if (depth!=1 and depth!=2):
         testResult('fail','findDict: the argument - depth can\'t be the values other than 1 or 2',log)
         log.info('findDict: the argument - depth can\'t be the values other than 1 or 2')
         return 0
    if depth==1:
         for key in inputDict.keys():
             if key not in outputDict.keys():
                 testResult('fail','findDict: the key - {0} in inputDict is not found in outputDict'.format(key),log)
                 log.info('findDict: the key - {0} in inputDict is not found in outputDict'.format(key))
                 return 0
             elif (type(inputDict[key])==list and set(inputDict[key])!=set(outputDict[key])):
                 testResult('fail','findDict: the list value of key - {0} in inputDict is not the same as outputDict, expected: {1}, actual: {2}'.format(key,inputDict[key],outputDict[key]),log)
                 log.info('findDict: the list value of key - {0} in inputDict is not the same as outputDict'.format(key))
                 return 0
             elif (type(inputDict[key])!=list and inputDict[key]!=outputDict[key]):
                 testResult('fail','findDict: the value of key - {0} in inputDict is not the same as outputDict, expected: {1}, actual: {2}'.format(key,inputDict[key],outputDict[key]),log)
                 log.info('findDict: the value of key - {0} in inputDict is not the same as outputDict'.format(key))
                 return 0
         log.info('findDict: inputDict was found in outputDict')
         return 1
    if depth==2:
         for key1 in inputDict.keys():
             if key1 not in outputDict.keys():
                 testRsult('fail','findDict: the key - {0} in inputDict is not found in outputDict'.format(key1),log)
                 log.info('findDict: the key - {0} in inputDict is not found in outputDict'.format(key1))
                 return 0
             else:
                 for key2 in inputDict[key1].keys():
                     if key2 not in outputDict[key1].keys():
                          testResult('fail','findDict: the 2nd-level key - {0} for 1st-level {1} in inputDict is not found in outputDict'.format(key2,key1),log)
                          log.info('findDict: the 2nd-level key - {0} for 1st-level {1} in inputDict is not found in outputDict'.format(key2,key1))
                          return 0 
                     elif (type(inputDict[key1][key2])==list and set(inputDict[key1][key2])!=set(outputDict[key1][key2])):
                          testResult('fail','findDict: the list value of 2nd-level key - {0} for 1st-level {1} in inputDict is not the same as outputDict,\
                               expected:{2}, actual: {3}'.format(key2,key1,inputDict[key1][key2],inputDict[key1][key2]),log)
                          log.info('findDict: the list value of 2nd-level key - {0} for 1st-level {1} in inputDict is not the same as outputDict'.format(key2,key1))
                          return 0
                     elif (type(inputDict[key1][key2])!=list and inputDict[key1][key2]!=outputDict[key1][key2]):
                          testResult('fail','findDict: the value of 2nd-level key - {0} for 1st-level {1} in inputDict is not the same as outputDict, expected: {2}, actual: {3}'.format(key2,key1,inputDict[key1][key2],outputDict[key1][key2]),log)
                          log.info('findDict: the value of 2nd-level key - {0} for 1st-level {1} in inputDict is not the same as outputDict'.format(key2,key1))
                          return 0
                        
         log.info('findDict: inputDict was found in outputDict')
         return 1




#Function to normalize the interface names to the uniformed ones
#e.g. Ethernet3/1,ethernet3/1,Eth3/1,eth3/1,Et3/1,et3/1 => Eth3/1
#     Portchannel10,portchannel10,Port-channel10, port-channel10, Po10,po10 => Po10
#     Vlan10,vlan10,vl10,Vl10 => Vlan10
#The function can take string, list,tuple,dictionary as input, and replace the various 
#interface name to the uniformed one. For dictionary, it replace interface name in key. 
#######################################################################################
def normalizeInterfaceName(log,interface):
     in_type=type(interface)
     pattern1='[Ee]thernet|[Ee]th|[Ee]t'
     pattern2='[Vv]lan|[Vv]l'
     pattern3='[Pp]ort-channel|[Pp]ortchannel|[Pp]o'
     pattern4='[Ll]oopback|[Ll]oop-back|[Ll]o'
     pattern5='[Nn]ve'
     if (in_type == str):
         interface=re.sub(r'(?:{0})((?:{1}))'.format(pattern1,rex.INTERFACE_NUMBER),r'Eth\1',interface)
         interface=re.sub(r'(?:{0})((?:{1}))'.format(pattern2,rex.INTERFACE_NUMBER),r'Vlan\1',interface)
         interface=re.sub(r'(?:{0})((?:{1}))'.format(pattern3,rex.INTERFACE_NUMBER),r'Po\1',interface)
         interface=re.sub(r'(?:{0})((?:{1}))'.format(pattern4,rex.INTERFACE_NUMBER),r'Lo\1',interface)
         interface=re.sub(r'(?:{0})((?:{1}))'.format(pattern5,rex.INTERFACE_NUMBER),r'Nve\1',interface)
     if (in_type == list):
         for int in interface:
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern1,rex.INTERFACE_NUMBER),r'Eth\1',int)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern2,rex.INTERFACE_NUMBER),r'Vlan\1',tmp)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern3,rex.INTERFACE_NUMBER),r'Po\1',tmp)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern4,rex.INTERFACE_NUMBER),r'Lo\1',tmp)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern5,rex.INTERFACE_NUMBER),r'Nve\1',tmp)
             interface[interface.index(int)]=tmp
     if (in_type == tuple):
         int_list=list(interface)
         for int in int_list:
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern1,rex.INTERFACE_NUMBER),r'Eth\1',int)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern2,rex.INTERFACE_NUMBER),r'Vlan\1',tmp)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern3,rex.INTERFACE_NUMBER),r'Po\1',tmp)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern4,rex.INTERFACE_NUMBER),r'Lo\1',tmp)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern5,rex.INTERFACE_NUMBER),r'Nve\1',tmp)
             int_list[int_list.index(int)]=tmp
         interface=tuple(int_list)
     if (in_type == dict):
         dct={}
         for key in interface.keys():
             int=re.sub(r'(?:{0})((?:{1}))'.format(pattern1,rex.INTERFACE_NUMBER),r'Eth\1',key)
             int=re.sub(r'(?:{0})((?:{1}))'.format(pattern2,rex.INTERFACE_NUMBER),r'Vlan\1',int)
             int=re.sub(r'(?:{0})((?:{1}))'.format(pattern3,rex.INTERFACE_NUMBER),r'Po\1',int)
             int=re.sub(r'(?:{0})((?:{1}))'.format(pattern4,rex.INTERFACE_NUMBER),r'Lo\1',int)
             int=re.sub(r'(?:{0})((?:{1}))'.format(pattern5,rex.INTERFACE_NUMBER),r'Nve\1',int)
             tmp={int:interface[key]}
             dct.update(tmp)
         interface=dct

     return interface

def getFullInterfaceName(log,interface):
     """ 
     This is opposite of normalizeInterfaceName method. This returns full interface name as needed
     in some NxOS commands
     """

     in_type=type(interface)
     pattern1='[Ee]thernet|[Ee]th|[Ee]t'
     pattern2='[Vv]lan|[Vv]l'
     pattern3='[Pp]ort-channel|[Pp]ortchannel|[Pp]o'
     if (in_type == str):
         interface=re.sub(r'(?:{0})((?:{1}))'.format(pattern1,rex.INTERFACE_NUMBER),r'Ethernet\1',interface)
         interface=re.sub(r'(?:{0})((?:{1}))'.format(pattern2,rex.INTERFACE_NUMBER),r'Vlan\1',interface)
         interface=re.sub(r'(?:{0})((?:{1}))'.format(pattern3,rex.INTERFACE_NUMBER),r'Port-channel\1',interface)
     if (in_type == list):
         for int in interface:
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern1,rex.INTERFACE_NUMBER),r'Ethernet\1',int)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern2,rex.INTERFACE_NUMBER),r'Vlan\1',tmp)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern3,rex.INTERFACE_NUMBER),r'Port-channel\1',tmp)
             interface[interface.index(int)]=tmp
     if (in_type == tuple):
         int_list=list(interface)
         for int in int_list:
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern1,rex.INTERFACE_NUMBER),r'Ethernet\1',int)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern2,rex.INTERFACE_NUMBER),r'Vlan\1',tmp)
             tmp=re.sub(r'(?:{0})((?:{1}))'.format(pattern3,rex.INTERFACE_NUMBER),r'Port-channel\1',tmp)
             int_list[int_list.index(int)]=tmp
         interface=tuple(int_list)
     if (in_type == dict):
         dct={}
         for key in interface.keys():
             int=re.sub(r'(?:{0})((?:{1}))'.format(pattern1,rex.INTERFACE_NUMBER),r'Ethernet\1',key)
             int=re.sub(r'(?:{0})((?:{1}))'.format(pattern2,rex.INTERFACE_NUMBER),r'Vlan\1',int)
             int=re.sub(r'(?:{0})((?:{1}))'.format(pattern3,rex.INTERFACE_NUMBER),r'Port-channel\1',int)
             tmp={int:interface[key]}
             dct.update(tmp)
         interface=dct

     return interface
 
#======================================================================================#
# getActiveVdcList - Method to get list of vdc names or vdc ids in active state
#       
# mandatory args: hdl, log
# Optional arg: -vdcid  -option to return list of active vdc ids
#                       - by default returns list of active vdc names
#      Usage Examples: getActiveVdcList(hdl, log)
#                      getActiveVdcList(hdl, log, '-vdcid')
#     Returned List examples: ['vdc6', 'vdc5', 'vdc4', 'vdc3', 'vdc2', 'vdc8', 'N7K4']
#                           ['1', '3', '2', '5', '4', '6', '8'] 
#======================================================================================#
def getActiveVdcList(hdl, log, *args):
    arggrammar={}
    arggrammar['vdcid']='-type bool'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return ''

    vdc_output=hdl.execute('show vdc')
    pattern='^([0-9]+)[ \t]+([a-zA-Z0-9_\-]+)[ \t]+([a-zA-Z]+)[ \t]+({0})[ \t]+([a-zA-Z]+)[ \t]+([a-zA-Z0-9]+.*)\r'.format(rex.MACADDR)
    vdc_out=re.findall(pattern, vdc_output, re.M)
   
    if options_namespace.vdcid:
         vdc_dict=convertListToDict(vdc_out,['vdc_id','vdc_name','state','mac','type','lc'],['vdc_id'])
    else:
         vdc_dict=convertListToDict(vdc_out,['vdc_id','vdc_name','state','mac','type','lc'],['vdc_name'])
     
    vdc_list=[]
    for vdc in vdc_dict.keys():
        if vdc_dict[vdc]['state']=='active':
            vdc_list.append(vdc)
    msg='Active vdcs are {0}'.format(vdc_list)    
    log.info(msg)
    return vdc_list

def getSysmgrServiceStateDict(hdl, log, *args):

    # Return the service state in dict format

    # Sample Usage:
    # getSysmgrServiceStateDict (hdl, log, '-services pixm')
    # getSysmgrServiceStateDict (hdl, log, '-services pixm ospf')

    arggrammar={}
    arggrammar['services']='-type str -required True'
    arggrammar['module']='-type int'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    # Extract all the services in a list
    if parse_output.services in ["PFMCLNT","ExceptionLog"]:
        services = re.findall((rex.ALPHANUMSPECIAL),parse_output.services)
    else:
        services = re.findall((rex.ALPHANUMSPECIAL),parse_output.services.lower())
    # get all needed pattern here
    split_pattern = 'Service \"'
    pattern1 = 'Service \"({0})\" +'.format(rex.SYSMGR_SERVICE_NAME)
    pattern2 = 'UUID = (0x{0}), +-- +Currently not running +--'.format(rex.HEX)
    pattern3 = 'UUID = (0x{0}), +PID = ({1}), +SAP = ({1})'.format(rex.HEX,rex.NUM)
    pattern4 = 'State: +({0})'.format(rex.ALPHASPECIAL)
    pattern5 = 'Restart count: +({0})'.format(rex.NUM)
    # Intitialize the return variable
    service_info = {}
    for name in services:
        if not parse_output.module:
           cmd_out = hdl.execute ('show system internal sysmgr service name {0}'.format(name))
        else:
           cmd_out = hdl.execute ('slot {0} show system internal sysmgr service name {1}'.format(parse_output.module,name))
        cmd_out_list=cmd_out.split(split_pattern)
        for index in range(1,len(cmd_out_list)):
            # Add the split pattern to the part
            cmd_out_list[index] = split_pattern + cmd_out_list[index] 
            match=re.search(pattern1,cmd_out_list[index])
            if match:
                s_name = match.group(1)
                service_info[s_name] = {}
            else:
                log.error ('No Match found for service ' + str(name))
                break
            match=re.search(pattern2,cmd_out_list[index])
            if match:
                service_info[s_name]['UUID'] =  match.group(1)
                service_info[s_name]['Service_State'] = 'Not_Running'
                continue
            match=re.search(pattern3,cmd_out_list[index])            
            if match:
                service_info[s_name]['UUID'] =  match.group(1)
                service_info[s_name]['PID'] = match.group(2)
                service_info[s_name]['SAP'] = match.group(3)
            match=re.search(pattern4,cmd_out_list[index])            
            if match:
                service_info[s_name]['Service_State'] =  match.group(1)
                match=re.search(pattern5,cmd_out_list[index])            
            if match:
                service_info[s_name]['Restart_Count'] =  match.group(1)
        pass
    # return the state of each services in dict format
    return service_info


def restartService(hdl,log,service,*args):
    
    """Restart a given service for given instance (optional)
    # Sample Usage:
    # restartService (hdl, log, 'pixm')
    # restartService (hdl, log, 'ospf', '-signal 9 -instance 2')
    # restartService (hdl, log, 'ospf')

    """
    arggrammar={}
    arggrammar['instance']= '-type str'
    arggrammar['module']= '-type int'
    arggrammar['signal']= '-type str -default 9'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if service not in ["PFMCLNT","ExceptionLog"]:
        service = service.lower()
    signal = parse_output.signal
    module=parse_output.module
    if (parse_output.instance) and not parse_output.module:
        pid = getServicePid (hdl,log,service,'-instance {0}'.format(parse_output.instance))
    elif parse_output.module:
        pid = getServicePid (hdl,log,service,'-module {0}'.format(parse_output.module))
    else:
        pid = getServicePid (hdl,log,service)
    if (pid <= 0):
        log.info ('Service {0} is not running'.format(service))
        return False
    linux_cmd = 'kill -{0} {1}'.format(signal,pid)
    if module:
        hdl.bashexec(linux_cmd,'-module {0}'.format(parse_output.module))
    else:
        hdl.bashexec(linux_cmd)
    # Wait for restarted service to come in stable condition
    time.sleep(1)
    new_pid = 0
    iteration = 0
    while (new_pid <=0) and (iteration < 5):
        log.info ('Checking iteration:{0} for service:{1}'.format(iteration,service))
        iteration += 1
        if (parse_output.instance) and not parse_output.module:
            new_pid = getServicePid (hdl,log,service,'-instance {0}'.format(parse_output.instance))
        elif parse_output.module:
            new_pid = getServicePid (hdl,log,service,'-module {0}'.format(parse_output.module))
        else:
            new_pid = getServicePid (hdl,log,service)
        if (iteration == 5):
            log.info ('Service {0} didn"t restart'.format(service))
            return False
        time.sleep(1)
    if (new_pid == pid):
        log.info ('Service {0} didn"t restart properely'.format(service))
        return False
    else:
        return True
        
##################################################################################

def getServicePid(hdl, log,name, *args):
    
    # Return the PID for a given service, instance (optional)
    
    # Sample Usage:
    # getServicePid (hdl, log, 'pixm')
    # getServicePid (hdl, log, 'ospf', '-instance 2')
    # getServicePid (hdl, log, 'ospf')
    
    arggrammar={}
    arggrammar['instance']= '-type str'
    arggrammar['module']= '-type int'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if name not in ["PFMCLNT","ExceptionLog"]:
        name = name.lower()
    # Get the service info
    if not parse_output.module:
        service_info = getSysmgrServiceStateDict(hdl,log, '-service ' + str (name))
    else:
        service_info = getSysmgrServiceStateDict(hdl,log, '-service {0} -module {1}'.format(name,parse_output.module))
    if len(service_info.keys()) > 1:
        # See if instance option was passed
        if parse_output.instance:
            instance = parse_output.instance
        else:
            instance = '1'
        # my key is used in case service has multiple pid       
        mykey = '__inst_{0}__{1}'.format(instance.zfill(3),name)
        # Walk through all services and return the state for matching instance
        # This code block will get executed if service has multiple instance e.g. ospf
        # Default PID is returned for instance 1 else whatever instance was passed
        for key in service_info.keys():
            if (key == mykey) and (service_info[key]['Service_State'] == 'SRV_STATE_HANDSHAKED'):
                return service_info[key]['PID'] 
            pass
    elif (len(service_info.keys()) == 1):
        for key in service_info.keys():
            if (service_info[key]['Service_State'] == 'SRV_STATE_HANDSHAKED'):
                return service_info[key]['PID'] 
            else:
                log.info ('Service may not be running, return PID as 0')
                return 0
    else:
        # no services for that name or service not running
        log.info ('Service info not found, return PID as 0')        
        return 0
    # If no match so far
    log.info ('Service may not be running or no info for service:'+ name)
    return 0




def getSysmgrState(hdl, log, *args):

    # Return the service state in dict format

    # Sample Usage:
    # getSysmgrState (hdl, log, '-vdc N7K2')
    # getSysmgrState (hdl, log, '-vdc default')
    # vdc name is required parameter so user don't overlook non def vdcs

    arggrammar={}
    arggrammar['vdc']='-type str -require True'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    # Extract vdc name
    vdc_name  = parse_output.vdc.lower()
    if vdc_name == 'default':
        cmd = 'show system internal sysmgr state'
    else:
        cmd = 'show system internal sysmgr vdc {0} state'.format(vdc_name)
        
    # get all needed pattern here
    pattern1 = 'The state is ({0}) entered at time'.format(rex.ALPHASPECIAL)
    pattern2 = 'Local super-state is: +({0})'.format(rex.ALPHASPECIAL)
    pattern3 = 'Standby super-state is: +({0})'.format(rex.ALPHASPECIAL)
    pattern4 = 'Total number of Switchovers: +({0})'.format(rex.NUM)
    pattern5 = 'Last switchover took : +({0}) +secs'.format(rex.DECIMAL_NUM)
    # Initialize the state
    sysmgr_state ={}
    # Get the command output
    cmd_out = hdl.execute (cmd)
    match=re.search(pattern1,cmd_out)
    if match:
       sysmgr_state['State'] = match.group(1)
    match=re.search(pattern2,cmd_out)
    if match:
       sysmgr_state['Local_State'] = match.group(1)
    match=re.search(pattern3,cmd_out)
    if match:
       sysmgr_state['Standby_State'] = match.group(1)
    match=re.search(pattern4,cmd_out)
    if match:
       sysmgr_state['Switchover_Count'] = match.group(1)
    match=re.search(pattern5,cmd_out)
    if match:
       sysmgr_state['Switchover_Time'] = match.group(1)
    # return the state of each services in dict format
    return sysmgr_state

#======================================================================================#
# getVdcHaStandbyStateDict - Method to get dict of Ha state of vdcs
#
# mandatory args: hdl, log
# optional args: vdc - a vdc or list of vdcs
#     Usage Examples: getVdcHaStandbyStateDict(hdl, log)
#                     getVdcHaStandbyStateDict(hdl, log, '-vdcid 1, 4, 2')
#                     getVdcHaStandbyStateDict(hdl, log, '-vdcid 1 4 9')
#     Returned Dictionary Example:                
#                  {'1': {'Other_supervisor': 'HA standby', 'This_supervisor': 'Active with HA standby'}, '4': {'Other_supervisor': 'HA standby', 'This_supervisor': 'Active with HA standby'}}
#======================================================================================#
def getVdcHaStandbyStateDict( hdl, log, *args):
    msg='Fetch HA state of vdcs'
    log.info(msg)
    
    arggrammar={}
    arggrammar['vdcid'] = ''

    optionsNamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if optionsNamespace.vdcid:
        vdcstr=optionsNamespace.vdcid
        vdc_list=strtolist(vdcstr)
    else:
       vdc_list=getActiveVdcList(hdl, log, '-vdcid')    

    log.info('Getting HA info for vdcs -{0}'.format(vdc_list))
    output=hdl.execute('show system redundancy ha status')
    pat='^vdc[ \t]+([0-9]+)[ \t]+([a-zA-Z]+[ ]+[a-zA-Z]+[ ]+[a-zA-Z]+[ ]+[a-zA-Z]+)[ \t]+([^ ]+.*)[ \t]+\r'
    vdc_ha_list=re.findall(pat, output, re.M)
    if len(vdc_ha_list)==0:
        log.info('Vdc HA status available on default vdc only')
        return {}
    vdc_ha_out_dict={}
    vdc_ha_dict=convertListToDict(vdc_ha_list,['VDC_No','This_supervisor','Other_supervisor'],['VDC_No'])
    for vdc in vdc_list:
        if vdc not in vdc_ha_dict.keys():
            log.info('vdc {0} is not an active vdcid on Dut'.format(vdc))
        else:        
            vdc_ha_out_dict[vdc]=vdc_ha_dict[vdc]
            vdc_ha_out_dict[vdc]['Other_supervisor']=vdc_ha_dict[vdc]['Other_supervisor'].strip(' ')
    log.info('Vdc HA Dict - {0}'.format(vdc_ha_out_dict))
    return vdc_ha_out_dict    

#======================================================================================#
# getLineCardList - Method to get list of lc module numbers
#
# mandatory args: hdl, log
# optional args: -status: List of LC modules in this status
#                -model: List of LC modules with this model
#     Usage Examples: getLineCardList(hdl, log)
#                     getLineCardList(hdl, log, '-Status ok')
#                     getLineCardList(hdl, log, '-Model N7K-F248XT-25')
#     Returned Dictionary Example:                
#                      ['3', '4']
#======================================================================================#

def getLineCardList(hdl, log, *args):

    arggrammar={}
    arggrammar['Status']='-type str'
    arggrammar['Model']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    msg='Fetch list of line card modules on {0}'.format(hdl.switchName)
    log.info(msg)
    sw_cmd="show module"
    if ns.Status: 
        status=ns.Status
    else:
        status=rex.LC_STATUS
    if ns.Model:
        model=ns.Model
    else:
        model=rex.LC_MODEL

    show_mod=hdl.execute(sw_cmd)

    # This needs to be change for EOR 
    #pat='([0-9]+)[ \t]+[0-9]+[ \t]+{2}[ \t]+{0}[ \t]+{1}'.format(model,status,rex.LC_MODULE_TYPE)
    print (model)
    print (status)
    print (rex.LC_MODULE_TYPE)
    pat='([0-9]+)[ \t]+[0-9]+[ \t]+{2}[ \t]+{0}[ \t]+{1}'.format(model,status,rex.LC_MODULE_TYPE)
    mod_list=re.findall( pat, show_mod, flags=re.I )
    if len(mod_list)==0:
         msg='No Line Card Module was found on {0}'.format(hdl.switchName)
         print(msg)
         log.info(msg)
    print (mod_list)
    return mod_list


#======================================================================================#
# getModuleSlotList - Method to get list of module numbers based on type 
#
# mandatory args: hdl, log
#     Usage Examples: getModuleSlotList(hdl, log)
#                     getModuleSlotList(hdl, log, type='LC')
#                     getModuleSlotList(hdl, log, type='FM')
#                     getModuleSlotList(hdl, log, type='SC')
#     Returned Dictionary Example:                
#                      ['3', '4']
#======================================================================================#
def getModuleSlotList(hdl, log, type='LC'):
    cmd = 'show module'
    
    output = hdl.execute(cmd)
    lines = output.split('\n')
    status = 'ok|active'
    pattern = r'^([0-9]+)[ \t]+.*({0})'.format(status)
    slot_set = Set([])

    for line in lines:
        match = re.search(pattern, line)
        if match: 
           mod_slot = match.group(1)
           if int(mod_slot) < 17 and type == 'LC':
              slot_set.add(mod_slot)
           elif int(mod_slot) > 20 and int(mod_slot) < 26 and type == 'FM':
              slot_set.add(mod_slot)
           elif int(mod_slot) > 28 and int(mod_slot) < 31 and type == 'SC':
              slot_set.add(mod_slot)
    return slot_set
           
   
#======================================================================================#
# checkCCResult - Method to check consistency checker result 
#
# mandatory args: hdl, cmd, log
#     Usage Examples: checkCCResult(hdl, cmd, log)
#     Returned integer: 0 - PASS
#                       1 - FAIL                
#======================================================================================#
def checkCCResult(hdl, cmd, log):
    result = 0
    iterations = 15
    while iterations:
      # some commands need longer time   
      # output = hdl.execute(cmd)
      hdl.hdl.sendline(cmd)
      hdl.hdl.expect('# $',timeout=180)
      output = hdl.hdl.before
      hdl.hdl.sendline('\r')
      print(output)
      match = re.search('in progress', output)
      if match:
        time.sleep(10)
        iterations = iterations - 1
      else:
        break

    match = re.search('FAIL', output)
    if match:
        result = 1
        testResult('fail', '{0}: Consistency-checker FAILED: {1}'.format(hdl.switchName, cmd), log)
    return result

#======================================================================================#
# getIpPrefixList - Method to get dictionary of prefix-lists
#
# mandatory args: hdl, log
# optional args: prefix-list name and seq
#     Usage Examples: getIpPrefixList(hdl, log)
#                     getIpPrefixList(hdl, log, '-prefix_list test')
#                     getIpPrefixList(hdl, log, '-prefix_list test -seq 10')
#     Returned Dictionary Example:  
#                  {'test': OrderedDict([('10', OrderedDict([('action', 'permit'), ('ip_subnet', '13.0.0.0'), ('mask_len', '16'), ('mask_range', 'ge 17 le 27')])), ('15', OrderedDict([('action', 'permit'), ('ip_subnet', '100.0.0.0'), ('mask_len', '20'), ('mask_range', 'ge 23 le 32')])), ('20', OrderedDict([('action', 'permit'), ('ip_subnet', '100.0.0.0'), ('mask_len', '20'), ('mask_range', 'le 30')]))])}              
#======================================================================================#
def getIpPrefixList( hdl, log, *args):
    return_dict={}
    sw_cmd='show ip prefix-list '
    log.info('Fetching IP prefix-list on {0}'.format(hdl.getSwitchName()))  
    arggrammar={}
    arggrammar['prefix_list']='-type str'
    arggrammar['seq']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,'namespace')
   
    if ns.prefix_list:
        log.info('Using prefix_list passed by user ' + str(ns.prefix_list) )
        sw_cmd= sw_cmd + ns.prefix_list
        
        if ns.seq:
            sw_cmd=sw_cmd+' seq '+ns.seq
            out=hdl.execute(sw_cmd)
            
            seq_pattern='[ \t]+seq[ \t]+([0-9]+)[ \t]+([a-zA-Z]+)[ \t]+({0})\/([0-9]+)[ \t]+((?:le|ge|eq).*)?\r'.format(rex.IP_ADDRESS)
            out_seq=re.findall(seq_pattern,out,re.M)
            if len(out_seq)==0:
                return return_dict
            else:
                seq_dict=convertListToDict(out_seq,['seq','action', 'ip_subnet', 'mask_len', 'mask_range'],['seq'])
                for key in seq_dict.keys():
                    seq_dict[key]['mask_range']=seq_dict[key]['mask_range'].strip(' ')
                return_dict[ns.prefix_list]=seq_dict
                return return_dict
        
    if ns.seq and (not ns.prefix_list):
        log.info('Invalid usage: seq cannot be specified without prefix-list')
        return return_dict
    
    if (not ns.prefix_list) and (not ns.seq):
        sw_cmd='show ip prefix-list'       
    
    output=hdl.execute(sw_cmd)      
    split_pattern='ip prefix-list '
    ## Splitting output into blocks for each prefix-list
    out_list=output.split(split_pattern)
    out_list.pop(0)
    out_pref=[]
    prefix_dict={}
    for out in out_list:
        out_sp=str(split_pattern)+out
        pref='ip prefix-list'
        pattern='{0}[ \t]+([a-zA-Z0-9_\-#!]+):[ \t]([0-9]+)[ \t]+entries'.format(pref)
        ## Getting list of  seq in each prefix list
        out_pref=re.findall(pattern,out_sp,re.M)
        prefix=out_pref[0][0]
        no_entries=out_pref[0][1]
        seq_pattern='[ \t]+seq[ \t]+([0-9]+)[ \t]+([a-zA-Z]+)[ \t]+({0})\/([0-9]+)[ \t]+((?:le|ge|eq).*)?\r\n'.format(rex.IP_ADDRESS)
        out_seq=re.findall(seq_pattern,out,re.M)
        ## Build dictinary of all seq for each prefix-list
        seq_dict=convertListToDict(out_seq,['seq','action', 'ip_subnet', 'mask_len', 'mask_range'],['seq'])
        for key in seq_dict.keys():
            seq_dict[key]['mask_range']=seq_dict[key]['mask_range'].strip(' ')
        ## Create prefix-list dictionary with all seq dictionaries
        return_dict[prefix]=seq_dict

    return return_dict 

def getMacAddressTableDict (hdl, log, *args):
    arggrammar={}
    arggrammar['address']= '-position 2'
    arggrammar['dynamic']= '-position 5 -type bool'
    arggrammar['interface']= '-position 6'
    arggrammar['secure']= '-position 3 -type bool'
    arggrammar['static']= '-position 4 -type bool'
    arggrammar['vlan']= '-position 7 -type int'
    arggrammar['module']= '-position 1 -type int'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if ns.module: 
        command = "show mac address-table " + str(ns.module) + " " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str",["module"])
        showOutput = hdl.execute(command)
        macaddrList=re.findall("(\S+)\s+(\S+)\s+(\S+)\s+([0-9a-fA-F\.]+)\s+(static|dynamic)\s+(\S+)\s+(\S+)\s+(\S+)\s+([^\r\n]+)\r\n",showOutput)
        return convertListToDict(macaddrList,['Flag','FE','VLAN','MAC_Address','Type','age','Secure','NTFY','Port'],['FE','MAC_Address','VLAN'])
    else:
        command = "show mac address-table " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
        showOutput = hdl.execute(command)
        #Pick common field between EOR and N7K
        #macaddrList=re.findall("(\S+)\s+(\S+)\s+([0-9a-fA-F\.]+)\s+(static|dynamic)\s+\S+\s+\S+\s+\S+\s+([^\r\n]+)\r",showOutput)
        macaddrList=re.findall("([\*\+A-Z ]+)\s+(\S+)\s+([0-9a-fA-F\.]+)\s+(static|dynamic)\s+\S+\s+\S+\s+\S+\s+([^\r\n]+)\r",showOutput)
        return convertListToDict(macaddrList,['Flag','VLAN','MAC_Address','Type','Port'],['MAC_Address','VLAN'])

def getL2fmMacdbDict (hdl,log,*args):
    """
    Method to parse and retrurn l2fm info and MAC,VLAN key
    """

    arggrammar={}
    arggrammar['vlan']='-type str -format {0}'.format(rex.NUM)
    parse=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    cmd = 'show system internal l2fm info macdb'
    if parse.vlan:
        cmd += ' vlan {0}'.format(parse.vlan)
    cmd_out = hdl.execute(cmd)
    pattern = '\s+({0})\s+({1})\s+({2})\s+[0-9]+\.[0-9]+\.[0-9a-fA-F]+\s+0x[0-9]+\s+(?:0x)?[0-9]+\s+\[([01])[01][01][01][01][01][01][01]\]\s+bm'\
        .format(rex.NUM,rex.MACADDR,rex.INTERFACE_NAME)
    mac_list = re.findall(pattern,cmd_out)
    return convertListToDict(mac_list,['VLAN','MAC_Address','Ports','P'],['MAC_Address','VLAN'])



#======================================================================================#
# getInterfaceErrorCounter - Method to get a dictionary of error counter on given interface list
#
# mandatory args: hdl, log, interfaces
# optional args: 
#               
#     Usage Examples: getInterfaceErrorCounter(hdl, log,'ether3/1, eth3/4')
#     Returned Dictionary Example:                
#{'Eth3/1': {'Carri-Sen': '0', 'Deferred-Tx': '0', 'FCS-Err': '0', 'Giants': '0', 'Align-Err': '0', 'OutDiscards': '0', 'Xmit-Err': '0', 'Symbol-Err': '0', 'Late-Col': '0', 'IntMacRx-Er': '0', 'Rcv-Err': '0', 'Exces-Col': '0', 'SQETest-Err': '--', 'Multi-Col': '0', 'Runts': '0', 'IntMacTx-Er': '0', 'UnderSize': '0', 'Single-Col': '0'}, 'Eth3/4': {'Carri-Sen': '0', 'Deferred-Tx': '0', 'FCS-Err': '0', 'Giants': '0', 'Align-Err': '0', 'OutDiscards': '0', 'Xmit-Err': '0', 'Symbol-Err': '0', 'Late-Col': '0', 'IntMacRx-Er': '0', 'Rcv-Err': '0', 'Exces-Col': '0', 'SQETest-Err': '--', 'Multi-Col': '0', 'Runts': '0', 'IntMacTx-Er': '0', 'UnderSize': '0', 'Single-Col': '0'}}
#
#                      
#======================================================================================#

def getInterfaceErrorCounter(hdl, log, interfaces):
    msg='Fetch interfce error counters on interaces {0} on {1}'.format(interfaces,hdl)
    log.info(msg)
    int_list=strtolist(interfaces)
    ret_dict={}
    for int in int_list:
       sw_cmd="show interface {0} counters errors".format(int)
       output=hdl.execute(sw_cmd)
       cnt='[0-9\-]+'
       space='[ \t]+'
       pattern='({0}){1}({2}){1}({2}){1}({2}){1}({2}){1}({2}){1}({2})'.format(rex.INTERFACE_NAME,space,cnt)
       output_list=output.split('\r\n\r\n')
       num=0
       dict={}
       for line in output_list:
           match=re.search(pattern,line,re.I)
           if match and num==0:
               key=match.group(1)
               dict={'Align-Err':match.group(2),'FCS-Err':match.group(3),'Xmit-Err':match.group(4),
                     'Rcv-Err':match.group(5),'UnderSize':match.group(6),'OutDiscards':match.group(7)}
               num+=1
               continue
           if match and num==1:
               tmp={'Single-Col':match.group(2),'Multi-Col':match.group(3),'Late-Col':match.group(4),
                     'Exces-Col':match.group(5),'Carri-Sen':match.group(6),'Runts':match.group(7)}
               dict.update(tmp)
               num+=1
               continue
           if match and num==2:
               tmp={'Giants':match.group(2),'SQETest-Err':match.group(3),'Deferred-Tx':match.group(4),
                     'IntMacTx-Er':match.group(5),'IntMacRx-Er':match.group(6),'Symbol-Err':match.group(7)}
               dict.update(tmp)
       if match:
           tmp={key:dict}
           ret_dict.update(tmp)
       
    return ret_dict        


#======================================================================================#
# getInterfaceInputCounter - Method to get the number of Input Unicast Packets from
# "show interface ethx/y counters" output
#
# mandatory args: hdl, log, interface
#======================================================================================#

def getInterfaceInputCounter(hdl, log, intf):

    log.info('Fetch interfce unicast input counters on interace {0} on {1}'.format(intf,hdl))
    inputPktCounter=0

    show_int="show interface {0} counters | begin InOctets next 2".format(intf)
    output=hdl.execute(show_int)
    output_list=output.split('\r')

    for line in output_list:
        pat='\S+\s+[0-9]+\s+([0-9]+)'
        inputPktCounter=re.findall( pat, line)
        log.info('inputPktCounter: {0}'.format(inputPktCounter))
        if inputPktCounter != []:
          return listtostr(inputPktCounter)

    return inputPktCounter

#======================================================================================#
# getInterfaceOutCounter - Method to get the number of Output Unicast Packets from
# "show interface ethx/y counters" output
#
# mandatory args: hdl, log, interface
#======================================================================================#

def getInterfaceOutputCounter(hdl, log, intf):

    log.info('Fetch interfce unicast output counters on interace {0} on {1}'.format(intf,hdl))
    outputPktCounter=0

    show_int="show interface {0} counters | begin OutOctets next 2".format(intf)
    output=hdl.execute(show_int)
    output_list=output.split('\r')

    for line in output_list:
        pat='\S+\s+[0-9]+\s+([0-9]+)'
        outputPktCounter=re.findall( pat, line)
        log.info('outputPktCounter: {0}'.format(outputPktCounter))
        if outputPktCounter != []:
          return listtostr(outputPktCounter)

    return outputPktCounter

#======================================================================================#
# getInterfaceOutCounter - Method to get the number of Output Unicast Packets from
# "show interface ethx/y counters" output
#
# mandatory args: hdl, log, interface
#======================================================================================#

def getInterfaceOutputRate(hdl, log, intf):

    log.info('Fetch interfce unicast output counters on interace {0} on {1}'.format(intf,hdl))
    outputPktRate=0

    show_int="show interface {0} counters brief".format(intf)
    output=hdl.execute(show_int)
    output_list=output.split('\r')

    for line in output_list:
        pat='\S+\s+[0-9.]+\s+[0-9.]+\s+([0-9.]+)\s+'
        outputPktRate=re.findall( pat, line)
        log.info('outputPktRate: {0}'.format(outputPktRate))
        if outputPktRate != []:
          return listtostr(outputPktRate)

    return outputPktRate


#####################################
def retIpAddressList (ip_info):

    # Returns list of ip addresses, accepts input as string which
    # has start_ip, end_ip and increment parameter

    # Usage:
    # retIpAddressList ('10.1.1.1, 10.1.1.10, 1')
    # Default increment 1
    # retIpAddressList ('10.1.1.1, 10.1.1.10)
    # retIpAddressList ('10.1.1.1')

    ip_info_list = ip_info.split(',')
    if (len(ip_info_list) == 1):
        # only start_ip passed
        return ip_info_list
    elif (len(ip_info_list) == 2):
        # default incr 1
        start_ip = ipaddr.IPv4Address(ip_info_list[0].strip())
        last_ip = ipaddr.IPv4Address(ip_info_list[1].strip())
        incr_ip = 1
    else:
        # accept the user given incr
        start_ip = ipaddr.IPv4Address(ip_info_list[0].strip())
        last_ip = ipaddr.IPv4Address(ip_info_list[1].strip())
        incr_ip = int(ip_info_list[2].strip())
    # Initialize the ip_list variable
    ip_list = []
    while (start_ip <= last_ip):
        ip_list.append(str(start_ip))
        start_ip += incr_ip
    return ip_list

#####################################
def retIpv6AddressList (ip_info):

    # Returns list of ipv6 addresses, accepts input as string which
    # has start_ip, end_ip and increment parameter
    # The returned IPv6 address is always in a full 128-bit format

    # Usage:
    # retIpAddressList ('2001::1, 2001::10, 1')
    # Default increment 1
    # retIpAddressList ('2001::1, 2001::10')
    # retIpAddressList ('2001::1')

    ip_info_list = ip_info.split(',')
    if (len(ip_info_list) == 1):
        # only start_ip passed
        return ipaddr.IPv6Address(ip_info_list[0]).exploded.split()
    elif (len(ip_info_list) == 2):
        # default incr 1
        start_ip = ipaddr.IPv6Address(ip_info_list[0].strip())
        last_ip = ipaddr.IPv6Address(ip_info_list[1].strip())
        incr_ip = 1
    else:
        # accept the user given incr
        start_ip = ipaddr.IPv6Address(ip_info_list[0].strip())
        last_ip = ipaddr.IPv6Address(ip_info_list[1].strip())
        incr_ip = int(ip_info_list[2].strip())
    # Initialize the ip_list variable
    ip_list = []
    while (start_ip <= last_ip):
        ip_list.append(str(start_ip.exploded))
        start_ip += incr_ip
    return ip_list


#======================================================================================#
# getHsrpGroupDict - Method to get dictionary of HSRP
#
# mandatory args: hdl, log
# optional args: active,all,group,init,interface,ipv4,learn,listen,speak,standby
#     Usage Examples: getHsrpGroupDict(hdl, log)
#                     getHsrpGroupDict(hdl, log, '-active')
#                     gethsrpGroupDict(hdl, log, '-interface <interface>')
#     Returned Dictionary Example:  
#{'Vlan101': {'Hellotime': '3', 'Group': '0', 'state changes': '2', 'Standby router is': 'unknown', 'Authentication text': 'cisco', 'Forwarding threshold(for vPC), upper': '100', 'Forwarding threshold(for vPC), lower': '1', 'priority': '100', 'last state change': '01:45:07', 'state': 'Active', 'Active router': 'local', 'IP redundancy name': 'hsrp-Vlan101-0', 'Virtual IP address': '1.1.2.1', 'holdtime': '10', 'Next hello sent in': '1.884000', 'Virtual mac address': '0000.0c07.ac00'}, 'Vlan100': {'Hellotime': '3', 'Group': '0', 'state changes': '2', 'Standby router is': 'unknown', 'Authentication text': 'cisco', 'Forwarding threshold(for vPC), upper': '100', 'Forwarding threshold(for vPC), lower': '1', 'priority': '100', 'last state change': '01:51:07', 'state': 'Active', 'Active router': 'local', 'IP redundancy name': 'hsrp-Vlan100-0', 'Virtual IP address': '1.1.1.1', 'holdtime': '10', 'Next hello sent in': '1.885000', 'Virtual mac address': '0000.0c07.ac00'}, 'Ethernet1/10': {'Hellotime': '3', 'Group': '0', 'state changes': '2', 'Standby router is': 'unknown', 'Authentication text': 'cisco', 'Forwarding threshold(for vPC), upper': '100', 'Forwarding threshold(for vPC), lower': '1', 'priority': '100', 'last state change': '01:38:58', 'state': 'Active', 'Active router': 'local', 'IP redundancy name': 'hsrp-Eth1/10-0', 'Virtual IP address': '1.1.3.1', 'holdtime': '10', 'Next hello sent in': '1.884000', 'Virtual mac address': '0000.0c07.ac00'}}
#======================================================================================#
def getHsrpDict (hdl,log,*args):

    arggrammar={}
    arggrammar['active']= '-type bool'
    arggrammar['all']= '-type bool'
    arggrammar['group']= '-type int'
    arggrammar['init']='-type bool'
    arggrammar['interface']=''
    arggrammar['ipv4']='-type bool'
    arggrammar['learn']='-type bool'
    arggrammar['listen']='-type bool'
    arggrammar['speak']='-type bool'
    arggrammar['standby']='-type bool' 

    cmd="show hsrp " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    showhsrp=hdl.execute(cmd)

    hsrpgroups=showhsrp.split("\r\n\r\n")
    hsrpdict={}
    for elem in hsrpgroups:
        key=[]
        findlist=re.findall("("+rex.INTERFACE_NAME+")",elem)
        if len(findlist):
           key.append(normalizeInterfaceName(log, findlist[0]))
           findlist=re.findall("Group\s+(\d+)",elem)
           if len(findlist):
              key.append(findlist[0])
              key=tuple(key)
              hsrpdict[key]={}
           else:
              continue
        else:
           continue
        findlist=re.findall("Local state is\s+([^,]+)",elem)
        if len(findlist):
           hsrpdict[key]['state']=findlist[0]
        findlist=re.findall("priority\s+(\d+)",elem)
        if len(findlist):
           hsrpdict[key]['priority']=findlist[0]
        findlist=re.findall("lower:\s+(\d+)",elem)
        if len(findlist):
           hsrpdict[key]['Forwarding threshold(for vPC), lower']=findlist[0]
        findlist=re.findall("upper:\s+(\d+)",elem)
        if len(findlist):
           hsrpdict[key]['Forwarding threshold(for vPC), upper']=findlist[0]
        findlist=re.findall("Hellotime\s+(\d+)",elem)
        if len(findlist):
           hsrpdict[key]['Hellotime']=findlist[0]
        findlist=re.findall("holdtime\s+(\d+)",elem)
        if len(findlist):
           hsrpdict[key]['holdtime']=findlist[0]
        findlist=re.findall("Next hello sent in\s+(\S+)",elem)
        if len(findlist):
           hsrpdict[key]['Next hello sent in']=findlist[0]
        findlist=re.findall("Virtual IP address is\s+(\S+)",elem)
        if len(findlist):
           hsrpdict[key]['Virtual IP address']=findlist[0]
        findlist=re.findall("Active router is\s+(\S+)",elem)
        if len(findlist):
           hsrpdict[key]['Active router']=findlist[0]
        findlist=re.findall("Standby router is\s+(\S+)",elem)
        if len(findlist):
           hsrpdict[key]['Standby router is']=findlist[0]
        findlist=re.findall("Authentication text\s+\"([^\"]+)",elem)
        if len(findlist):
           hsrpdict[key]['Authentication text']=findlist[0]
        findlist=re.findall("Virtual mac address is ("+rex.MACADDR+")",elem) 
        if len(findlist):
           hsrpdict[key]['Virtual mac address']=findlist[0]
        findlist=re.findall("(\d+)\s+state changes",elem) 
        if len(findlist):
           hsrpdict[key]['state changes']=findlist[0]
        findlist=re.findall("last state change\s+(\S+)",elem)
        if len(findlist):
           hsrpdict[key]['last state change']=findlist[0]
        findlist=re.findall("IP redundancy name is\s+(\S+)",elem)
        if len(findlist):
           hsrpdict[key]['IP redundancy name']=findlist[0]

    #log.debug("HSRP dictionary is " + str(hsrpdict))
    return hsrpdict 

#======================================================================================#
# getVrrpv2Dict - Method to get dictionary of VRRP
#
# mandatory args: hdl, log
# optional args: backup,init,vr,interface,master
#     Usage Examples: getHsrpGroupDict(hdl, log)
#                     getHsrpGroupDict(hdl, log, '-master')
#                     gethsrpGroupDict(hdl, log, '-interface <interface>')
#     Returned Dictionary Example:  
#{('Vlan9', '9'): {'Forwarding threshold upper': '100', 'Preemption': 'enabled', 'Virtual MAC address': '0000.5e00.0109',\
#    'Priority Configured': '100', 'Priority': '100', 'Forwarding threshold lower': '1', 'State': 'Master', \
#     'Advertisement interval': '1', 'Master router': 'Local'}, ('Ethernet6/40', '11'): {'Forwarding threshold upper': '100',\
#      'Preemption': 'enabled', 'Virtual MAC address': '0000.5e00.010b', 'Priority Configured': '100', 'Priority': '100',\
#      'Forwarding threshold lower': '1', 'State': 'Init', 'Advertisement interval': '1', 'Master router': 'Unknown'},\
#       ('port-channel50', '50'): {'Forwarding threshold upper': '100', 'Preemption': 'enabled', 'Virtual MAC address': \
#       '0000.5e00.0132', 'Priority Configured': '100', 'Priority': '100', 'Forwarding threshold lower': '1', \
#       'State': 'Init', 'Advertisement interval': '1', 'Master router': 'Unknown'}}
#======================================================================================#

def getVrrpv2Dict (hdl,log,*args):

    arggrammar={}
    arggrammar['backup']= '-type bool'
    arggrammar['init']='-type bool'
    arggrammar['vr']= '-type int'
    arggrammar['interface']=''
    arggrammar['master']='-type bool'

    cmd="show vrrp detail " + parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    showvrrp=hdl.execute(cmd)

    returndict={}    
    for vrrpgroup in showvrrp.split("\r\n\r\n"):
        key=[]
        findlist=re.findall("("+rex.INTERFACE_NAME+")",vrrpgroup)
        if len(findlist):
           key.append(normalizeInterfaceName(log, findlist[0]))
           findlist=re.findall("Group\s+(\d+)",vrrpgroup)
           if len(findlist):
              key.append(findlist[0])
              key=tuple(key)
              returndict[key]={}
           else:
              continue
        else:
           continue
        findlist=re.findall("[0-9]+/s+\(([A-Z0-9]+)\)",vrrpgroup)
        if len(findlist):
            returndict[key]['IpVersion']=findlist[0] 
        findlist=re.findall("State is ([A-Za-z]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['State']=findlist[0] 
        findlist=re.findall("Virtual IP address is ({0})".format(rex.IP_ADDRESS),vrrpgroup)
        if len(findlist):
            returndict[key]['Virtual_IP_address']=findlist[0] 
        findlist=re.findall("Priority ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Priority']=findlist[0] 
        findlist=re.findall("Configured ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Priority_Configured']=findlist[0] 
        findlist=re.findall("lower: ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Forwarding_threshold_lower']=findlist[0] 
        findlist=re.findall("upper: ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Forwarding_threshold_upper']=findlist[0] 
        findlist=re.findall("Advertisement interval ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Advertisement_interval']=findlist[0] 
        findlist=re.findall("Preemption ([A-Za-z]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Preemption']=findlist[0] 
        findlist=re.findall("Virtual MAC address is ("+rex.MACADDR+")",vrrpgroup)
        if len(findlist):
            returndict[key]['Virtual_MAC_address']=findlist[0] 
        findlist=re.findall("Master router is ([A-Za-z0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Master_router']=findlist[0] 

    log.debug("VRRP dictionary is " + str(returndict))
    return returndict


#======================================================================================#
# getVrrpv3Dict - Method to get dictionary of VRRP
#
# mandatory args: hdl, log
# optional args: backup,init,vr,interface,master
#     Usage Examples: getHsrpGroupDict(hdl, log)
#                     getHsrpGroupDict(hdl, log, '-master')
#                     gethsrpGroupDict(hdl, log, '-interface <interface>')
#     Returned Dictionary Example:  
#{('Vlan9', '9'): {'Forwarding threshold upper': '100', 'Preemption': 'enabled', 'Virtual MAC address': '0000.5e00.0109',\
#    'Priority Configured': '100', 'Priority': '100', 'Forwarding threshold lower': '1', 'State': 'Master', \
#     'Advertisement interval': '1', 'Master router': 'Local'}, ('Ethernet6/40', '11'): {'Forwarding threshold upper': '100',\
#      'Preemption': 'enabled', 'Virtual MAC address': '0000.5e00.010b', 'Priority Configured': '100', 'Priority': '100',\
#      'Forwarding threshold lower': '1', 'State': 'Init', 'Advertisement interval': '1', 'Master router': 'Unknown'},\
#       ('port-channel50', '50'): {'Forwarding threshold upper': '100', 'Preemption': 'enabled', 'Virtual MAC address': \
#       '0000.5e00.0132', 'Priority Configured': '100', 'Priority': '100', 'Forwarding threshold lower': '1', \
#       'State': 'Init', 'Advertisement interval': '1', 'Master router': 'Unknown'}}
#======================================================================================#

def getVrrpv3Dict (hdl,log,*args):

    arggrammar={}
    arggrammar['backup']= '-type bool'
    arggrammar['init']='-type bool'
    arggrammar['vr']= '-type int'
    arggrammar['interface']=''
    arggrammar['master']='-type bool'
    arggrammar['addr_family']='-type str'

    ns = parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    addr_family=ns.addr_family
    cmd="show vrrpv3 {0}".format(addr_family)
    showvrrp=hdl.execute(cmd)

    returndict={}
    for vrrpgroup in showvrrp.split("\r\n\r\n"):
        key=[]
        findlist=re.findall("("+rex.INTERFACE_NAME+")",vrrpgroup)
        if len(findlist):
           key.append(normalizeInterfaceName(log, findlist[0]))
           findlist=re.findall("Group\s+(\d+)",vrrpgroup)
           if len(findlist):
              key.append(findlist[0])
              key=tuple(key)
              returndict[key]={}
           else:
              continue
        else:
           continue
        findlist=re.findall("[0-9]+/s+\(([A-Z0-9]+)\)",vrrpgroup)
        if len(findlist):
            returndict[key]['IpVersion']=findlist[0]
        findlist=re.findall("State is ([A-Za-z]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['State']=findlist[0]
        findlist=re.findall("Virtual IP address is ({0})".format(rex.IP_ADDRESS),vrrpgroup)
        if len(findlist):
            returndict[key]['Virtual_IP_address']=findlist[0]
        findlist=re.findall("Priority is ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Priority']=findlist[0]
        findlist=re.findall("Configured ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Priority_Configured']=findlist[0]
        findlist=re.findall("lower: ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Forwarding_threshold_lower']=findlist[0]
        findlist=re.findall("upper: ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Forwarding_threshold_upper']=findlist[0]
        findlist=re.findall("Advertisement interval ([0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Advertisement_interval']=findlist[0]
        findlist=re.findall("Preemption ([A-Za-z]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Preemption']=findlist[0]
        findlist=re.findall("Virtual MAC address is ("+rex.MACADDR+")",vrrpgroup)
        if len(findlist):
            returndict[key]['Virtual_MAC_address']=findlist[0]
        findlist=re.findall("Master router is ([A-Za-z0-9]+)",vrrpgroup)
        if len(findlist):
            returndict[key]['Master_router']=findlist[0]

    log.debug("VRRP dictionary is " + str(returndict))
    return returndict


##########################################################################################

def compareVarsErrMessageHelper(item_and_types,var1):
    '''Generate the string to be printed in case compareVars fails.'''
    #This is a helper function for compareVars

    orig_type=item_and_types[0]
    # This is to convert tuples to lists
    if orig_type is tuple:
        item_and_types.pop(0)
        orig_type=type([])
        item_and_types.insert(0,orig_type)

    # Init print_struct
    if orig_type is list:
        print_struct=[]
    elif orig_type is tuple:
        print_struct=()
    elif orig_type is dict:
        print_struct={}
    else:
        print_struct=''
    prev_type=orig_type
    temp_struct=print_struct

    # Build the print_struct 
    index=-1
    for item,curr_type in zip(item_and_types[1::2],item_and_types[2::2]):
        index+=2

        # This is to convert tuples to list for printing
        #if curr_type is tuple:
        #    item_and_types.pop(index+1)
        #    curr_type=type([])
        #    item_and_types.insert(index+1,curr_type)

        if prev_type is list:
            if curr_type is list:
                temp_struct.append([])
            elif curr_type is tuple:
                temp_struct.append(item)
            elif curr_type is dict:
                temp_struct.append({})
            elif curr_type is str:
                temp_struct.append(item)
            elif curr_type is int:
                temp_struct.append(item)
            temp_struct=temp_struct[-1]
        elif prev_type is tuple:
            # Should never be here since tuples are treated same as str/int (immutable)
            if curr_type is list:
                temp_struct+=([],)
            elif curr_type is tuple:
                temp_struct+=((),)
            elif curr_type is dict:
                temp_struct+=({},)
            elif curr_type is str:
                temp_struct+=(item,)
            elif curr_type is int:
                temp_struct+=(item,)
            # Since tuples are immutable, cant really do this below, hence the print will break
            # Alternate is to print tuples as lists or treat them as basic types
            temp_struct=temp_struct[-1]
        elif prev_type is dict:
            if curr_type is list:
                temp_struct.update({item:[]})
            elif curr_type is tuple:
                temp_struct.update({item:deepcopy(var1)})
            elif curr_type is dict:
                temp_struct.update({item:{}})
            elif curr_type is str:
                temp_struct.update({item:deepcopy(var1)})
            elif curr_type is int:
                temp_struct.update({item:deepcopy(var1)})
            temp_struct=temp_struct[item]
        prev_type=curr_type

    return str(print_struct)


def compareVars(var1,var2,log,*args,**kwargs):
    '''Checks to see if var1 is a proper subset or equal to var2.
    
    Return 'pass' if var1 is a proper subset or equal to var2
    Return 'fail' if var2 is not a superset of var1
    
    Sample usage:
      result=compareVars(a,b,log)
      result=compareVars(a,b,log,'-equal') # To check if var1=var2
      result=compareVars(a,b,log,'-allfailures') # To print all mismatches
   
    This function returns after the first mismatch is observed
    With '-allfailures' flag, it tries to find all mismatches
    All mismatches are printed to the 'log'
    
    The **kwargs is used for internal purposes only'''
    
    fail_message=kwargs.get('fail_message',[])
    print_all_failures=kwargs.get('print_all_failures',0)
    compare_for_equal=kwargs.get('compare_for_equal',0)

    if args:
        arggrammar={}
        arggrammar['equal']='-type bool'
        arggrammar['allfailures']='-type bool'
        options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
        if not options_namespace.VALIDARGS:
            log.warning('Invalid arguments')
            return ''

        # If '-allfailures' is specified then print all mismatches
        if options_namespace.allfailures:
            print_all_failures=1

        # If '-equal' match then call compareVars twice as below
        if options_namespace.equal:
            compare_for_equal=1

    # Figure out if this call is in recursion or not for printing proper fail_message
    if inspect.stack()[1][3] == inspect.stack()[0][3]:
        # In recursion
        first_call=0
    else:
        first_call=1
        # Error out if user passes kwargs
        if kwargs:
            log.warning('Invalid arguments: Named arguments are for internal use only')
            return ''

    # Special case hack for -equal comparision
    if compare_for_equal==-1:
        first_call=1

    # If '-equal' match then call compareVars twice as below
    if compare_for_equal==1:
        log.info('\nResult for var1 compared to var2:\n=================================')
        result1=compareVars(var1,var2,log,print_all_failures=print_all_failures,compare_for_equal=-1)

        log.info('\nResult for var2 compared to var1:\n=================================')
        result2=compareVars(var2,var1,log,print_all_failures=print_all_failures,compare_for_equal=-1)

        if result1=='pass' and result2=='pass':
            return 'pass'
        else:
            return 'fail'

    var1_type=type(var1)
    var2_type=type(var2)

    if first_call==1:
        # Special case to allow for comparison of comma/space seperated string as a list
        # Only if the user is directly passing these variables (not in recursion)
        if var1_type is str and var2_type is list:
            var1=re.split('[ ,]+',var1)
            var1_type=type(var1)
        elif var1_type is list and var2_type is str:
            var2=re.split('[ ,]+',var2)
            var2_type=type(var1)
            
    # Treat collections.OrderedDict as dict
    if var1_type is collections.OrderedDict:
        var1_type=type({})
    if var2_type is collections.OrderedDict:
        var2_type=type({})

    item_and_types=kwargs.get('item_and_types',[var1_type])

    # Can optimize by calling this only if there is a failure. Later
    print_struct=compareVarsErrMessageHelper(item_and_types,deepcopy(var1))

    matched_indices_in_lists=[]

    # If the variable types are different then return fail
    if var1_type!=var2_type:
        #if not fail_message:
        fail_message.append('FAIL: type mismatch {0}'.format(print_struct))
        # This below shouldnt matter since this code runs only first call
        if print_all_failures==1:
            for msg in fail_message:
                log.warning('compareVars: '+msg)
        elif first_call==1:
            for msg in fail_message:
                log.warning('compareVars: '+msg)
        return 'fail'

    # If variables are of basic types then compare
    if var1_type is str or var1_type is int or var1_type is float or var1_type is tuple:
        if var1==var2:
            return 'pass'
        else:
            fail_message.append('FAIL: value mismatch {0}. Expected: {1} Found: {2}'.format(\
                print_struct,var1,var2))
            if first_call==1:
                for msg in fail_message:
                    log.warning('compareVars: '+msg)
            if not first_call:
                return ['fail', 0]
            return 'fail'

    # Some optimizations

    # Check to see if lists are already equal
    # Note: Tuples are not treated same as lists since they are truly ordered sets
    if var1_type is list:
        if sorted(var1)==sorted(var2):
            return 'pass'
    
    # Check to see if dict/OrderedDict are already equal
    if var1_type is dict:
        if var1==var2:
            return 'pass'

    # If variables are of type list then walk thru each element of var1
    # Note: Tuples are not treated same as lists since they are truly ordered sets
    per_level_status='pass'
    if var1_type is list:
        thislevel_fail_index=-1
        for item1_index,item1 in enumerate(var1):
            msg_index=len(fail_message)
            old_num_of_msgs=0
            sublevel_fail_index_old=-1
            found_flag=0
            for item2_index,item2 in enumerate(var2):
                if item2_index in matched_indices_in_lists:
                    continue
                item1_type=type(item1)
                item2_type=type(item2)
                # Treat collections.OrderedDict as dict
                if item1_type is collections.OrderedDict:
                    item1_type=type({})
                if item2_type is collections.OrderedDict:
                    item2_type=type({})
                if item1_type==item2_type:
                    item_and_types.append(deepcopy(item1))
                    item_and_types.append(type(item1))
                    result=compareVars(item1,item2,log,item_and_types=item_and_types,\
                        fail_message=fail_message,print_all_failures=print_all_failures)
                    del item_and_types[-1]
                    del item_and_types[-1]
                    if result=='pass':
                        found_flag=1
                        matched_indices_in_lists.append(item2_index)
                        break
                    else:
                        # Code to trim down message list if -allfailures is requested
                        # Idea here is to do a greedy match. For example:
                        # Lets say at a given level if item1 [1,2,3,4,5] is compared with
                        # item2 [1,2,6,4,5] and [1,2,3,7,5], then the function prints the 
                        # mismatch as '[4] not found' instead of '[3] not found'
                        sublevel_fail_index=result[1]
                        new_msg_index=len(fail_message)
                        new_num_of_msgs=new_msg_index - (msg_index + old_num_of_msgs)
                        if sublevel_fail_index > sublevel_fail_index_old:
                            if old_num_of_msgs > 0:
                                del fail_message[msg_index:msg_index+old_num_of_msgs]
                            old_num_of_msgs=new_num_of_msgs
                            sublevel_fail_index_old=sublevel_fail_index
                        elif sublevel_fail_index < sublevel_fail_index_old:
                            del fail_message[msg_index + old_num_of_msgs:]
                        elif sublevel_fail_index == sublevel_fail_index_old:
                            # Idea here is to identify the lowest number of mismatches
                            # For example: if at a given level you compare item1 [1,2,3,4,5] 
                            # with item2 [1,2,6] and [1,2,7,5] then the function prints the 
                            # mismatch as '[3] and [4] not found' 
                            # instead of '[3] [4] and [5] not found'
                            if new_num_of_msgs < old_num_of_msgs:
                                del fail_message[msg_index:msg_index+old_num_of_msgs]
                                old_num_of_msgs=new_num_of_msgs
                            else:
                                if old_num_of_msgs > 0:
                                    del fail_message[msg_index + old_num_of_msgs:]
                                else:
                                    old_num_of_msgs=new_num_of_msgs

            if not found_flag:
                if thislevel_fail_index==-1:
                    thislevel_fail_index=item1_index
                # Log this message only if no sub-level fail messages exist
                if not fail_message[msg_index:]:
                    fail_message.append('FAIL: \'{0}\' : not found, or the number '.format(item1) + \
                        'of occurances of it are not the same in both lists {0}'.format(print_struct))
                per_level_status='fail'
                if print_all_failures==0:
                    if first_call==1:
                        for msg in fail_message:
                            log.warning('compareVars: '+msg)
                        return 'fail'
                    else:
                        return ['fail', thislevel_fail_index]
            else:
                del fail_message[msg_index:]
        # Need to seperate out the fail_message and return status
        if print_all_failures==1 and per_level_status=='fail':
            if first_call==1:
                for msg in fail_message:
                    log.warning('compareVars: '+msg)
            else:
                return ['fail', thislevel_fail_index]
        return per_level_status

    # If variables are of type dictionary then walk thru each key of var1
    per_level_status='pass'
    if var1_type is dict:
        for item1 in var1.keys():
            msg_index=len(fail_message)
            found_flag=0
            if item1 in var2.keys():
                var1_item1_type=type(var1[item1])
                var2_item1_type=type(var2[item1])
                # Treat collections.OrderedDict as dict
                if var1_item1_type is collections.OrderedDict:
                    var1_item1_type=type({})
                if var2_item1_type is collections.OrderedDict:
                    var2_item1_type=type({})
                if var1_item1_type==var2_item1_type:
                    item_and_types.append(deepcopy(item1))
                    item_and_types.append(var1_item1_type)
                    result=compareVars(var1[item1],var2[item1],log,item_and_types=item_and_types,\
                        fail_message=fail_message,print_all_failures=print_all_failures)
                    del item_and_types[-1]
                    del item_and_types[-1]
                    if result=='pass':
                        found_flag=1
                        continue
                    else:
                        if not fail_message[msg_index:]:
                            fail_message.append('FAIL: Mismatched value for this key {0}'\
                                .format(print_struct))
                else:
                    fail_message.append('FAIL: Mismatched type for this key: {0} : in {1}'\
                        .format(item1,print_struct))
            else:
                fail_message.append('FAIL: Missing the key: \'{0}\' : in {1}'\
                    .format(item1,print_struct))
            if not found_flag:
                per_level_status='fail'
                if print_all_failures==0:
                    if first_call==1:
                        for msg in fail_message:
                            log.warning('compareVars: '+msg)
                    return 'fail'
            else:
                del fail_message[msg_index:]
        if print_all_failures==1 and per_level_status=='fail':
            if first_call==1:
                for msg in fail_message:
                    log.warning('compareVars: '+msg)
        return per_level_status


#======================================================================================#
# getVpcPeerLinkDict - Method to get vpc peer-link info
#   
# mandatory args: hdl, log
#======================================================================================#
def getVpcPeerLinkDict(hdl, log):
    # Fetch the vpc peer-link info
    log.info('Getting vpc peer-link info from {0}'.format(hdl.switchName))
    sw_cmd='show vpc | begin "vPC Peer-link status"'
    out=hdl.execute(sw_cmd)
    pattern1='([0-9]+)[ \t]+({0})[ \t]+([a-zA-z]+)[ \t]+([0-9\-,]+)[ \t]*\r'.format(rex.INTERFACE_NAME)
    peerLinkMatch=re.findall(pattern1, out, flags=re.I)
    peerLinkDict=convertListToDict(peerLinkMatch,['id','Port','Status', 'Active_vlans'])
    return peerLinkDict

##########################################################################

def getIgmpGroupCount (hdl, log, *args):
    
    # Sample Usage
    # getIgmpGroupCount (hdl,log)
    # getIgmpGroupCount (hdl,log, '-vrf default')
    # getIgmpGroupCount (hdl,log, '-flag sGCount')

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['flag']='-type str -choices ["sgcount","stargcount","total"] -default total'

    cmd = 'show ip igmp groups summary '
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.flag:
        flag = parse_output.flag.lower()
    if parse_output.vrf:
        cmd = cmd + 'vrf ' + parse_output.vrf
    
    #get the command output
    cmd_out = hdl.execute(cmd)
    #output pattern
    pattern = '({0})\s+({1})\s+({1})'.format(rex.VRF_NAME,rex.NUM)
    matchlist = re.findall(pattern,cmd_out)
    starGCount = 0
    sGCount = 0
    for item in matchlist:
        starGCount += int(item[1])
        sGCount += int(item[2])
    # return the count
    if (flag == 'stargcount'):
        return starGCount
    elif (flag == 'sgcount'):
        return sGCount
    elif (flag == 'total'):
        return sGCount+starGCount
    else:
        return -1
####################################################################################

def getPimRpDict (hdl,log, *args):

    # Sample Usage
    # getPimRpDict (hdl,log)
    # getPimRpDict (hdl,log, '-goup 225.1.1.1 -vrf default')

    # returns PimRP info dictionary format
    arggrammar={}
    arggrammar['vrf']='-type str -default default'
    arggrammar['group']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    cmd = 'show ip pim rp '
    if parse_output.group:
        cmd += parse_output.group
    vrf = parse_output.vrf 
    if (vrf != 'default'):
        cmd += ' vrf ' + parse_output.vrf
    # get the command output
    cmd_out = hdl.execute(cmd)
    # output pattern
    vrf_pattern = 'PIM RP Status Information for VRF "({0})"'.format(rex.VRF_NAME)
    RP_pattern = 'RP:\s+({0})'.format(rex.IPv4_ADDR)
    uptime_pattern = 'uptime:\s+({0})'.format(rex.UPTIME)
    exptime_pattern = 'expires:\s+({0})'.format(rex.XPTIME)
    group_pattern = 'group ranges:\s+([0-9\s\./]+)'
    # split pattern
    RP_split_pattern = 'RP: '
    cmd_out_list=cmd_out.split(RP_split_pattern)
    # Initialize the variable
    pim_rp = {}
    for index in range(1,len(cmd_out_list)):
        cmd_out_list[index] = RP_split_pattern + cmd_out_list[index] 
        match=re.search(RP_pattern,cmd_out_list[index])
        if match: 
            rp = match.group(1)
            pim_rp[rp]= {}
        else:
            continue
        match=re.search(uptime_pattern,cmd_out_list[index])
        if match: 
            pim_rp[rp]['uptime']=match.group(1)
        match=re.search(exptime_pattern,cmd_out_list[index])
        if match: 
            pim_rp[rp]['exptime']=match.group(1)
        match=re.search(group_pattern,cmd_out_list[index])
        if match: 
            pim_rp[rp]['groups']=re.findall(rex.NETADDR,match.group(1))
        pass
    return pim_rp


###########################################################
def getIgmpSnoopingSummaryDict (hdl, log, *args):
    
    # Sample Usage
    # getIgmpSnoopingSummaryDict (hdl,log)
    # getIgmpSnoopingSummaryDict (hdl,log, '-vlan 10')
    # getIgmpSnoopingSummaryDict (hdl,log, '-group 225.1.1.1 -source 10.1.1.1')

    # Return IGMP snooping group count for a given or all vlan. In addition it returns total of *,G
    # S,G entries
    # The output is returned in dictionary format

    arggrammar={}
    arggrammar['vlan']='-type str'
    arggrammar['group']='-type str'
    arggrammar['source']='-type str'

    cmd = 'show ip igmp snooping groups '
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.group:
        cmd = cmd + parse_output.group
    if parse_output.source:
        cmd = cmd + ' ' + parse_output.source
    if parse_output.vlan:
        cmd = cmd + ' vlan ' + parse_output.vlan
    cmd += ' summary'
    #get the command output
    cmd_out = hdl.execute(cmd)
    # Get the pattern to extract the info for all the vlan
    pattern = '({0})\s+([DE])\s+([DE])\s+({0})\s+({0})'.format(rex.NUM)
    matchlist = re.findall(pattern,cmd_out)
    igmp_snoop_dict ={}
    for item in matchlist:
        #Each item is a list
        vlan = item[0]
        igmp_snoop_dict[vlan] = {}
        igmp_snoop_dict[vlan]['Snoop'] = item[1]
        igmp_snoop_dict[vlan]['OMF'] = item[2]
        igmp_snoop_dict[vlan]['(*,G)-Count'] = item[3]
        igmp_snoop_dict[vlan]['(S,G)-Count'] = item[4]
    pattern = 'Total number of \(\*,G\) entries:\s+({0})'.format(rex.NUM)
    match=re.search(pattern,cmd_out,flags=re.I)
    if match:
        igmp_snoop_dict['TotalStarG'] = match.group(1)
    pattern = 'Total number of \(S,G\) entries:\s+({0})'.format(rex.NUM)
    match = re.search(pattern,cmd_out,flags=re.I)
    if match:
        igmp_snoop_dict['TotalSG'] = match.group(1)
    return igmp_snoop_dict    
    
####################################################################################
def getIgmpSnoopingVlanDict (hdl, log, vlan, *args):

    # Returns the dictionary of Igmp snooping Vlan output
    # e.g.
    # IGMP Snooping information for vlan 10
    # IGMP snooping enabled
    # Lookup mode: IP
    # Optimised Multicast Flood (OMF) disabled
    # IGMP querier present, address: 10.1.1.1, version: 2, i/f Vlan10
    # Querier interval: 125 secs
    # Querier last member query interval: 1 secs
    # Querier robustness: 2
    # Switch-querier disabled
    # IGMPv3 Explicit tracking enabled
    # IGMPv2 Fast leave disabled
    # IGMPv1/v2 Report suppression enabled
    # IGMPv3 Report suppression disabled
    # Link Local Groups suppression enabled
    # Router port detection using PIM Hellos, IGMP Queries
    # Number of router-ports: 1
    # Number of groups: 1
    # VLAN vPC function disabled
    # Active ports:
    #   Eth1/19     
    # Returned Dictionary:
    # {'querier_address': '10.1.1.1', 'intf': 'Vlan10', 'querier_interval': '125', 'no_of_router_ports': '1', 'no_of_groups': '1', 'active_ports': 'Eth1/19'}


    msg='Fetch details from show ip igmp snooping vlan output on switch {0}'.format(hdl.switchName)
    log.info(msg)

    arggrammer={}
    arggrammer['vlan']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    dict = {}
    sw_cmd = 'show ip igmp snooping'
    if str(ns) == 'Namespace()':
        msg = "Invalid arguments in method: getIgmpSnoopingVlanDict"
        print (msg)
        log.info(msg)
        return {}

    print ('vlan: {0}'.format(vlan))
    if vlan:
      sw_cmd+= ' vlan ' + vlan
    output = hdl.execute(sw_cmd)

    if (re.search('IGMP querier present, address: +([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',output,re.I)):
        dict={'querier_address':re.search('IGMP querier present, address: +([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',output,re.I).group(1)}

    if (re.search('IGMP querier present, address:.*i\/f ([A-Za-z0-9\/]+)',output,re.I)):
        tmp={'intf':re.search('IGMP querier present, address:.*i\/f ([A-Za-z0-9\/]+)',output,re.I).group(1)}
        dict.update(tmp)

    if (re.search('Querier interval: ([0-9]+)',output,re.I)):
        tmp={'querier_interval':re.search('Querier interval: ([0-9]+)',output,re.I).group(1)}
        dict.update(tmp)

    if (re.search('Number of router-ports: ([0-9]+)',output,re.I)):
        tmp={'no_of_router_ports':re.search('Number of router-ports: ([0-9]+)',output,re.I).group(1)}
        dict.update(tmp)

    if (re.search('Number of groups: ([0-9]+)',output,re.I)):
        tmp={'no_of_groups':re.search('Number of groups: ([0-9]+)',output,re.I).group(1)}
        dict.update(tmp)

    lines = output.split('\n')
    for line in lines:
        if (re.search('Active ports:',line)):
            nextLine = lines[lines.index(line)+1]
            tmp={'active_ports':re.findall(('\S+'),nextLine,re.I)}
            dict.update(tmp)

    return dict






# Added by sandesub    
#======================================================================================#
# getOspfv3NeighborDict - Method to get OSPFv3 neighbors information
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
# optional args
# CLI accepts only one of the optional arguments - vrf or interface
# vrf - vrf name to get ospfv3 neighbor dict in non-default vrf 
# interfaces - physical or vlan or port-channel
#              Example: '-interface vlan20' or 'interface eth3/1' or
#                       '-vrf test'  or '-interface po10'
# primary key of dict is (Neighbor_ID,Interface)
#======================================================================================#
def getOspfv3NeighborDict(hdl,log,*args):
        arggrammer={}
        arggrammer['vrf']='-type str'
        arggrammer['interface']=' -type str'
        arggrammer['mutualExclusive'] =[('vrf','interface')]
        ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
        sw_cmd="show ipv6 ospfv3 neighbors  "
        if ns.vrf:
              sw_cmd=sw_cmd + "vrf " + ns.vrf
        if ns.interface:
            sw_cmd= sw_cmd + " " + str(ns.interface)

        output=hdl.execute(sw_cmd)
        pattern="("+rex.IPv4_ADDR+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.ALPHAUPPER+")\/("+rex.ALPHAUPPER+")"
        pattern=pattern+"[ \t]+("+rex.UPTIME+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.INTERFACE_NAME+")"
        pattern=pattern+"\s+Neighbor address[ \t]+("+rex.LINK_LOCAL_IPv6_ADDR+")"
        neighbor_list=re.findall( pattern, output, flags=re.M )

        log.info("OSPFv3 Neighbor List: " + str(neighbor_list))
        neighbor_dict=convertListToDict(neighbor_list,['Neighbor_ID','Pri','State','Role','Up_Time','Interface_ID','Interface','Neighbor_Address'],['Neighbor_ID','Interface'])
        if len(neighbor_list)==0:
             msg='No ospfv3 neighbors found on {0}'.format(hdl.switchName)
             print(msg)
             log.info(msg)
        return neighbor_dict

# Added by sandesub
#======================================================================================#
# getOspfv3NeighborList - Method to get OSPFv3 neighbors information in list format
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
# optional args
# CLI accepts only one of the optional arguments - vrf or interface
# vrf - vrf name to get ospfv3 neighbor dict in non-default vrf 
# interfaces - physical or vlan or port-channel
#              Example: '-interface vlan20' or 'interface eth3/1' or
#                       '-vrf test'  or '-interface po10'
# Return format: [('Neighbor_Id', 'Interface') ...]
#======================================================================================#
def getOspfv3NeighborList(hdl,log,*args):
        ospfv3_nbr_dict = getOspfv3NeighborDict(hdl,log,*args)
        ospfv3_nbr_list = ospfv3_nbr_dict.keys()        
        log.info("OSPFv3 Neighbor List: " + str(ospfv3_nbr_list))
        return ospfv3_nbr_list
        

# Method to remove columns in a 2 level dictionary
def removeColumns (inputdict,*args):
    if not len(args):
        return inputdict
 
    returnDict=collections.OrderedDict()
    for key in inputdict.keys():
       returnDict[key]=collections.OrderedDict()
       for subkey in inputdict[key].keys():
           if subkey not in args:
              returnDict[key][subkey]=inputdict[key][subkey]
 
    return returnDict
 
# Added by sandesub    
#======================================================================================#
# getOspfv3InterfaceDict - Method to get OSPFv3 interface information
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
# optional args
# CLI accepts only one optional argument - vrf 
# vrf - vrf name to get ospfv3 interface dict in non-default vrf 
# primary key of dict is (Interface)
def getOspfv3InterfaceDict(hdl,log,*args):
        arggrammer={}
        arggrammer['vrf']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
        sw_cmd="show ipv6 ospfv3 interface brief  "
        if ns.vrf:
              sw_cmd=sw_cmd + "vrf " + ns.vrf
        output=hdl.execute(sw_cmd)
        pattern="("+rex.INTERFACE_NAME+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.IPv4_ADDR+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.ALPHAUPPER+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.ALPHA+")"
        intf_list=re.findall(pattern,output)
        log.info("Interface List: " + str(intf_list))
        intf_dict=convertListToDict(intf_list,['Interface','ID','Area','Cost','State','Neighbors','Status'],['Interface'])
        log.info("Interface Dict: " + str(intf_dict))
        if len(intf_list)==0:
             msg='No IPv6 interface found on {0}'.format(hdl.switchName)
             print(msg)
             log.info(msg)
        return intf_dict

# Added by sandesub
#======================================================================================#
# getOspfv3InterfaceList - Method to get OSPFv3 interface information in list format
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
# optional args
# CLI accepts only one of the optional arguments - vrf or interface
# vrf - vrf name to get ospfv3 interface list in non-default vrf 
# Return format: [('Interface') ...]
#======================================================================================#
def getOspfv3InterfaceList(hdl,log,*args):
        ospfv3_intf_dict = getOspfv3InterfaceDict(hdl,log,*args)
        ospfv3_intf_list = ospfv3_intf_dict.keys()        
        log.info("OSPFv3 Interface List: " + str(ospfv3_intf_list))
        return ospfv3_intf_list
        


def getMtsBuffersDetailDict(hdl, log, *args):
    # Returns dictionary format output of mts buffers detail of active sup and standby(if present)
    # In addition it can return similar output for other modules as specified
    # Return null dictionary for modules that arent available
    #
    # Sample return value:
    # ^^^^^^^^^^^^^^^^^^^^
    # First level key is the module ID
    # Second level key is (Node,SrcSAP,DstSAP,OPC) and message count with age>MAX_Q_AGE is the value
    # 1:
    # ('sup', '2356', '284', '86017'): 4
    # ('sup', '27170', '284', '86017'): 1
    # ('sup', '2816', '284', '86017'): 1
    # ('sup-1', '2835', '284', '86017'): 1
    # ('sup-2', '2593', '284', '86017'): 1
    # ('sup-3', '2659', '284', '86017'): 1
    
    arggrammar={}
    arggrammar['max_q_age']='-type str -format [0-9]+'
    arggrammar['module']='-type str -format [0-9,]+'
    arggrammar['fex']='-type str -format [0-9,]+'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if options_namespace.max_q_age:
        MAX_Q_AGE=options_namespace.max_q_age
    else:
        #MAX_Q_AGE=300000
        MAX_Q_AGE=10000

    system_mts_detail_dict={}

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return system_mts_detail_dict

    command='show system internal mts buffers detail | no-more'
    device_list=[]

    if options_namespace.module:
        module=options_namespace.module
        for device_id in str.split(module,','):
            device_list.append((device_id,'module'))
    if options_namespace.fex:
        fex=options_namespace.fex
        for device_id in str.split(fex,','):
            device_list.append((device_id,'fex'))

    # List of supervisor slots
    for sup_state in ['active','standby']:
        device_id=getSupervisorSlotNumber(hdl,log,'-state ' + sup_state)
        print(device_id)
        if device_id==0:
            continue
        else:
            device_list.append((device_id,sup_state))
            break
        # If sup slot was passed as a module then overwrite it 
        # such that we can do proper checks for success of 'attach' command
        try:
            index=[dev[0] for dev in device_list].index(device_id)
        except:
            device_list.append((device_id,sup_state))
        else:
            device_list[index]=(device_id,sup_state)

    print('Inside getMtsBuffersDetailDict')
    print(device_list)
    for device in device_list:
        device_id=int(device[0])
        device_type=device[1]

        if device_type=='active':
            show_output=hdl.execute(command)
        elif device_type=='standby':
            show_output=hdl.execute(command,'-{0}'.format(device_type))
        else:
            show_output=hdl.execute(command,'-{0} {1}'.format(device_type,device_id))

        if not show_output:
            log.warning('No output in slot {0} for command: {1}'.format(device_id,command))
            continue

        pattern='^([^ \t]+)[ \t]+([0-9]+)[ \t]+0x[0-9a-fA-F]+[ \t]+([0-9]+)[ \t]+0x[0-9a-fA-F]+[ \t]+([0-9]+)[ \t]+([0-9]+)'
        for line in show_output.splitlines():
            match=re.search(pattern,line,re.I)
            if (match and float(match.group(2))>float(MAX_Q_AGE)):
                node=re.sub('/[0-9]+/.*','',match.group(1))
                mt=re.search('\S+/(\d+)\\S+',match.group(1))
                srcsap=match.group(3)
                dstsap=match.group(4)
                opc=match.group(5) 
                age=match.group(2)
                if mt:
                    sap=mt.group(1)
                else:
                    sap=srcsap
                if device_id not in system_mts_detail_dict.keys():
                     system_mts_detail_dict[device_id]={}
                     #system_mts_detail_dict[device_id][(node,srcsap,dstsap,opc,age)]=1
                     system_mts_detail_dict[device_id][(node,srcsap,sap,dstsap,opc,age)]=1
                elif (node,srcsap,dstsap,opc,age) not in system_mts_detail_dict[device_id].keys():
                     #system_mts_detail_dict[device_id][(node,srcsap,dstsap,opc,age)]=1
                     system_mts_detail_dict[device_id][(node,srcsap,sap,dstsap,opc,age)]=1
                else:
                     #system_mts_detail_dict[device_id][(node,srcsap,dstsap,opc,age)]+=1
                     system_mts_detail_dict[device_id][(node,srcsap,sap,dstsap,opc,age)]+=1
                     
    return system_mts_detail_dict

#========================================================================================#
# getVpcConsistencyParametersDict - Returns the output of 
# 'show vpc consistency-parameters <options> in a dictionary format... Valid options are
#
# getVpcConsistencyParametersDict( hdl, log, '-flag global' )
# getVpcConsistencyParametersDict( hdl, log, '-flag vlans' )
# getVpcConsistencyParametersDict( hdl, log, '-interface po1' )
# getVpcConsistencyParametersDict( hdl, log, '-vpc 1' )
#
#========================================================================================#



def getVpcConsistencyParametersDict(hdl, log, *args):

    arggrammar={}
    arggrammar['flag']='-type str -choices ["global","vlans"]'
    arggrammar['interface']='-type str'
    arggrammar['vpc']='-type str'

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    vpc_consist_global_dict={}
    if ns.flag:
        if ns.flag=='global':
            show_vpc=hdl.execute("show vpc consistency-parameters global | begin 'STP Mode'")
        elif ns.flag=='vlans':
            show_vpc=hdl.execute("show vpc consistency-parameters vlans | begin 'STP Mode'")
        lines_out=re.findall( '(.*)\n', show_vpc, re.I )
        for line in lines_out:
            sub_line=re.sub( ' \s+', ':', line )
            line_list=str(sub_line).split(':')
            if len(line_list)==5:
                Name=line_list[0]
                if ns.flag=='vlans':
                    vpc_consist_global_dict[Name]=convertListToDict( line_list, ['Name', 'Type', 'Reason_Code',           \
                        'Pass_Vlans', 'ign' ]  )
                else:
                    vpc_consist_global_dict[Name]=convertListToDict( line_list, ['Name', 'Type', 'Local_Value',            \
                        'Peer_Value', 'ign' ]  )
        return vpc_consist_global_dict
    elif ns.interface:
        cmd='show vpc consistency-parameters interface {0} | begin STP'.format(ns.interface)
        show_vpc=hdl.execute(cmd)
        lines_out=re.findall( '(.*)\n', show_vpc, re.I )
        for line in lines_out:
            sub_line=re.sub( ' \s+', ':', line )
            line_list=str(sub_line).split(':')
            if len(line_list)==5:
                Name=line_list[0]
                vpc_consist_global_dict[Name]=convertListToDict( line_list, ['Name', 'Type', 'Local_Value', 'Peer_Value',    \
                        'ign' ]  )
        return vpc_consist_global_dict
    elif ns.vpc:
        cmd='show vpc consistency-parameters vpc {0} | begin STP'.format(ns.vpc)
        show_vpc=hdl.execute(cmd)
        lines_out=re.findall( '(.*)\n', show_vpc, re.I )
        for line in lines_out:
            sub_line=re.sub( ' \s+', ':', line )
            line_list=str(sub_line).split(':')
            if len(line_list)==5:
                Name=line_list[0]
                vpc_consist_global_dict[Name]=convertListToDict( line_list, ['Name', 'Type', 'Local_Value', 'Peer_Value',    \
                        'ign' ]  )
        return vpc_consist_global_dict

# Added by sandesub 
# getSpanningTreeTCNDict - method to get number of topology changes and timestamp on when the last TCN occured with VLAN as key
# Returns a dict; {<vlan-id> :{'tcns : <>', 'timestamp : <>'}}
def getSpanningTreeTCNDict(hdl,log,*args):
    arggrammar={}
    arggrammar['vlan']='-type int'
    argnamespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log,"str")
    cmd = "show spanning-tree " + parseoutput + "detail"
    log.info("Command: " + str(cmd))
    output=hdl.execute(cmd)
    pattern1="VLAN([0-9]+)[ \t]+is executing"
    pattern2="Number of topology changes[ \t]+("+rex.NUM+")[ \t]last change occurred[ \t]+("+rex.HH_MM_SS+")[ \t]+ago"
    list1=re.findall(pattern1,output,re.M)
    list2=re.findall(pattern2,output,re.M)
# Convert the vlans into int format
    intlist1 = []
    strlist1 = []
    list3 = []
    for item in list1 :
        intlist1.append(int(item))
# re-convert back into string
    for item in intlist1 :
        strlist1.append(str(item))
# logic to collapse the 2 lists
    for x in range (len(intlist1)):
        item2 = list2[x]
        item1 = strlist1[x]
        item2 = list(item2)
        item2.insert(0,item1)
        item2 = tuple(item2)
        list3.append(item2)
    out_dict=convertListToDict(list3,['vlan','tcns','timestamp'],['vlan'])
    log.info("Dict: " + str(out_dict))
    return out_dict


    
#========================================================================================#
# getLcListFromInterface - Returns the list of LCs that have port members for the given vlan/port-channels
#
# mandatory args: hdl, log, (vlan or port_channel)
# 
# getLcListFromInterface(hdl, log, '-vlan 1-5,301')
# getLcListFromInterface(hdl, log, '-port_channel po1,po2,po3')
# getLcListFromInterface(hdl, log, '-interface eth3/1, eth4/5')
# getLcListFromInterface(hdl, log, '-vlan 250-301 -port_channel po1,po2,po3')
#
# Returned list example : ['3', '6']
#
#========================================================================================#
def getLcListFromInterface(hdl, log, *args):
    
    arggrammar={}
    arggrammar['vlan']='-type str'
    arggrammar['port_channel']='-type str'
    arggrammar['interface']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,'namespace')
    
    port_list=[]
    pc_port_list=[]
    lc_list=[]
    remove_list=[]
    
    if parse_output.vlan:
        #Get all the member ports of the list/range of vlans
        vlan_list=strtoexpandedlist(parse_output.vlan)
        for vlan in vlan_list:
            vlandict=getVlanDict(hdl, log, '-vlan {0}'.format(vlan))
            #If vlan is not on Dut log msg
            if vlan not in vlandict.keys():
                log.info('Vlan {0} not on {1}'.format(vlan, hdl.switchName))
            else:
                port_list.extend(strtolist(vlandict[vlan]['Ports']))
        for port in port_list:
            # If member of vlan is port channel, get members of port-channel and add to list
            if re.search('po[0-9]+', port, re.I):
                pcmemlist=getPortChannelMemberList( hdl,log,'-pc_nam {0}'.format(port))
                remove_list.append(port)
                port_list.extend(pcmemlist)
    # Remove the port-channels from port_list after adding its member ports 
    for port in remove_list:
        port_list.remove(port)
     
    if parse_output.port_channel:
        #Get members of all port-channels and add to port_list
        pclist=strtolist(parse_output.port_channel)
        for pc in pclist:
            pcmemlist=getPortChannelMemberList( hdl,log,'-pc_nam {0}'.format(pc))
            pc_port_list.extend(pcmemlist)
    
    if parse_output.interface:
        #Added ports to port_list
        int_list=strtolist(parse_output.interface)
        for int in int_list:
            port_list.append(int)

    #Add ports from all port-channels to the list from vlans. Remove duplicates
    port_list.extend(pc_port_list)
    unique_port_list=set(port_list)
    plist=list(unique_port_list)
    #Get line card number form each port
    pattern='[a-zA-z]+([0-9]+)\/[0-9]+'
    for port in port_list:
        lc=re.findall(pattern, port)
        lc_list.extend(lc)
    unique_lc_set=set(lc_list)
    unique_lc_list=list(unique_lc_set)
    unique_lc_list.sort()
    log.info('LC list is {0}'.format(unique_lc_list))
    return unique_lc_list



# There're tabular outputs in the system where multiple columns can have spaces in the output 
#  and also column delimiter is space. When some of the columns are wrapped around, it makes 
#  it very difficult to parse.
# For e.g output as follows
# N7K1# show vpc consistency-parameters vpc 1 | begin "STP"
# STP Port Type               1     Default                Default               
# STP Port Guard              1     Default                Default               
# STP MST Simulate PVST       1     Default                Default               
# lag-id                      1     [(7f9b,                [(7f9b,               
#                                  0-1-55-55-55-55, 8001, 0-1-55-55-55-55, 8001,
#                                   0, 0), (8000,          0, 0), (8000,        
#                                  64-a0-e7-41-a5-43,     64-a0-e7-41-a5-43,    
#                                  8000, 0, 0)]           8000, 0, 0)]          
#mode                        1     active                 active                
#Speed                       1     10 Gb/s                10 Gb/s               
#Duplex                      1     full                   full                  
#Port Mode                   1     trunk                  trunk                 
#Native Vlan                 1     1                      1                     
#MTU                         1     1500                   1500                  
#vPC card type               1     Clipper                Clipper               
#Allowed VLANs               -     1-10                   1-10                  
#Local suspended VLANs       -     1                      -                     
#N7K1# exit
#
# One common theme in these output is that columns have maximum length & if they're beyond
# maximum length, then they're wrapped around. Making use of that aspect to get a more parsable
# output as follows by calling the following function with the above output & each column
# length. Resulting output is as follows where \t is the column separator all wrapped out
# output is included in one line
#
#STP Port Type        1        Default        Default
#STP Port Guard        1        Default        Default
#STP MST Simulate PVST        1        Default        Default
#lag-id        1        [(7f9b, 0-1-55-55-55-55, 8001, 0, 0), (8000, 64-a0-e7-41-a5-43, 8000, 0, 0)]        [(7f9b, 0-1-55-55-55-55, 8001, 0, 0), (8000, 64-a0-e7-41-a5-43, 8000, 0, 0)]
#mode        1        active        active
#Speed        1        10 Gb/s        10 Gb/s
#Duplex        1        full        full
#Port Mode        1        trunk        trunk
#Native Vlan        1        1        1
#MTU        1        1500        1500
#vPC card type        1        Clipper        Clipper
#Allowed VLANs        -        1-10        1-10
#Local suspended VLANs        -        1        
#
# Now this output can be re.findall("([^\t]+)\t([^\t]+)[\t]([^\t]+)[\t]([^\r]+)[\r\n]+",output)
# To get all the 4 columns in each
#
# Usage: getUnwrappedTable(<buffer>,<list of length of each column>)
#
# Example: getUnwrappedTable(output,[27,3,24,24])
# 

def getUnwrappedTable(output,columnlenghts,coldelimiter='\t'):

   prevcolumns={}
   returnoutput=""
   for i in range(len(columnlenghts)):
      prevcolumns[i]=""
   for line in output.split("\r\n"):
        columns={}
        columnstart=0
        for i in range(len(columnlenghts)):
            columns[i]=line[columnstart:columnstart+columnlenghts[i]].strip()
            columnstart=columnstart+columnlenghts[i]+1
        if len(columns[0]) == 0:
           for i in range(len(columnlenghts)):
              if len(columns[i]):
                  prevcolumns[i] = prevcolumns[i]+" "+columns[i]
           continue
        elif prevcolumns[0] != "":
           for i in range(len(columnlenghts)-1):
               returnoutput = returnoutput + prevcolumns[i] + coldelimiter
           returnoutput = returnoutput + prevcolumns[len(columnlenghts)-1] + "\r\n"
        for i in range(len(columnlenghts)):
            prevcolumns[i]=columns[i]
   for i in range(len(columnlenghts)-1):
       returnoutput = returnoutput + prevcolumns[i] + coldelimiter
   returnoutput = returnoutput + prevcolumns[len(columnlenghts)-1] + "\r\n"
   return returnoutput

# If your keys is like [('Vlan4', '4'), ('Vlan3', '3'), ('Vlan2', '2'), ('Vlan5', '5'), ('Vlan6', '2')]
# subkeys=['5','2']
# getKeys(subkeys,keys) will return
# [('Vlan5', '5'), ('Vlan2', '2'), ('Vlan6', '2')]

def getKeys(subkeys,keys):
   returnkeys=[]
   if len(keys):
      keytuplelen=len(keys[0])
   else:
      return returnkeys
   
   for subkey in strtolist(subkeys):
       result='false'
       if len(subkey.split()) < keytuplelen:
           for key in keys:
               if re.search("[\( ']"+subkey+"[',\)]",str(key)):
                   returnkeys.append(key)
                   result='true'
           if result=='false':
               print('key {0} is not in {1}'.format(subkey,keys))
       else:   
           returnkeys.append(subkey)
          
   return returnkeys

# If the string is '(Vlan100,0), (Ethernet1/10,0)'
# Then this will convert to
# [(Vlan100,0), (Ethernet1/10,0)]

def strtolistoftuple(inputstr,retainint=False):

   returnlist=[]
   inputstr=inputstr.strip('[')
   inputstr=inputstr.strip(']')
   for elem in inputstr.split(")"):
      elem=elem.strip(" ,(")
      if len(elem): 
         templist1=elem.split(",")
         templist2=[] 
         for subelem in templist1:
             subelem=subelem.strip("' ")
             subelem=subelem.strip('"')
             if subelem.isdigit() and retainint:
                 templist2.append(int(subelem))
             else:
                 templist2.append(subelem)
         returnlist.append(tuple(templist2))
   return returnlist

def getMldInterfaceDict(hdl,log,*args):
    #Returns the dictionary of mld interface info
    #Interface name is key
    #e.g.
    #Interface           IPv6 Address               MLD-Querier Members Version
    #Ethernet3/47        fe80::da67:d9ff:fe0a:4bc3  fe80::da67:d9ff:fe0a:4bc3  
    #                                                       1       v2
    #Vlan10              fe80::da67:d9ff:fe0a:4bc3  fe80::da67:d9ff:fe0a:4bc3  
    #                                                       1       v2

    #Returned dictionary:
    #OrderedDict([('Ethernet3/47', OrderedDict([('IPv6_Address', 'fe80::da67:d9ff:fe0a:4bc3'), ('MLD-Querier', 'fe80::da67:d9ff:fe0a:4bc3'), ('Members', '1'), ('Version', 'v2')])), ('Vlan10', OrderedDict([('IPv6_Address', 'fe80::da67:d9ff:fe0a:4bc3'), ('MLD-Querier', 'fe80::da67:d9ff:fe0a:4bc3'), ('Members', '1'), ('Version', 'v2')]))])

    msg='Fetch mld interface info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    members='[0-9]+'
    version='v[123]'
    dict={}
    sw_cmd='show ipv6 mld interface brief'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getMldInterfaceDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
  
    pattern='({0}) +({1}) +({1})[ \t\r\n]+({2}) +({3})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS,members,version)
    interface_list=re.findall(pattern,output,re.I)
    if (len(interface_list)):
        dict=convertListToDict(interface_list,['Interface','IPv6_Address','MLD-Querier','Members','Version'],'Interface')

    return dict

def getMldGroupsDict(hdl,log,*args):

    #Returns the dictionary of Mld groups info
    #(source,group,type,interface) is key
    #{'Uptime','Expires','Last_Reporter'} are the second-level keys
    #e.g.
    #  Group "ff03::7"
    #(2048::2, ff03::7)
    #  Type: Dynamic, Interface: Ethernet3/48
    #  Uptime/Expires: 07:20:50/00:03:18, Last Reporter: fe80::200:42ff:fe96:4fc8
    #
    #
    #Returned dictionary:
    #{('2048:0000:0000:0000:0000:0000:0000:0002', 'ff03:0000:0000:0000:0000:0000:0000:0007', 'Dynamic', 'Eth3/48'): {'Uptime': '07:20:50', 'Expires': '00:03:18', 'Last_Reporter': 'fe80::200:42ff:fe96:4fc8'}}

    msg='Fetch mld groups info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['group']='-type str'
    arggrammer['source']='-type str'
    arggrammer['interface']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    type='Static|Dynamic'
    source_ip='{0}|(?:\*)'.format(rex.IP_ADDRESS)
    eol='[ \t\r\n]+'
    dict={}
    sw_cmd='show ipv6 mld groups'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getMldGroupsDict"
         print (msg)
         log.info(msg)
         return {}
    if ns.group:
        sw_cmd+=' '+ns.group
    if ns.source:
        sw_cmd+=' '+ns.source
    if ns.interface:
        sw_cmd+=' '+ns.interface    
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    output_list=output.split('\r\n\r\n')

    pattern='\(({0}), +({1})\){2}Type: +({3}), +Interface: +({4}){2}Uptime/Expires: +({5})\/({6}), +Last Reporter: +({1})'\
            .format(source_ip,rex.IP_ADDRESS,eol,type,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME) 
    mld_dict={}
    for block in output_list:
        match=re.search(pattern,block,re.I)
        if match:
            if match.group(1) != '*' :
                 src=ipaddr.IPv6Address(match.group(1)).exploded
            else:
                 src='*'
            grp=ipaddr.IPv6Address(match.group(2)).exploded
            tmp_dict={(src,grp,match.group(3),normalizeInterfaceName(log,match.group(4))):{'Uptime':match.group(5),'Expires':match.group(6),'Last_Reporter':match.group(7)}}
            mld_dict.update(tmp_dict)

    return mld_dict

def getMldGroupCount (hdl, log, *args):
    
    # Sample Usage
    # getMldGroupCount (hdl,log)
    # getMldGroupCount (hdl,log, '-vrf default')
    # getMldGroupCount (hdl,log, '-flag sGCount')

    arggrammar={}
    arggrammar['vrf']='-type str'
    arggrammar['flag']='-type str -choices ["sgcount","stargcount","total"] -default total'

    cmd = 'show ipv6 mld groups'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.flag:
        flag = parse_output.flag.lower()
    if parse_output.vrf:
        cmd = cmd + 'vrf ' + parse_output.vrf
    
    #get the command output
    cmd_out = hdl.execute(cmd)
    #output pattern
    eol='[ \t\r\n]+'
    sg_pattern = '\(({0}), +({0})\){1}'.format(rex.IP_ADDRESS,eol)
    starg_pattern = '\(\*, +({0})\){1}'.format(rex.IP_ADDRESS,eol)
    cnt1 = len(re.findall(sg_pattern,cmd_out))
    cnt2 = len(re.findall(starg_pattern,cmd_out))

    # return the count
    if (flag == 'stargcount'):
        return cnt2
    elif (flag == 'sgcount'):
        return cnt1
    elif (flag == 'total'):
        return cnt1+cnt2

def getPim6InterfaceDict(hdl,log,*args):

    #Returns the dictionary of pim6 interface info
    #Interface name is key
    #e.g.
    #Interface          IPv6 Address/              Neighbor  Border
    #                   PIM6 DR Address            Count     Interface
    #Ethernet3/47       fe80::da67:d9ff:fe0a:4bc3  0         no
    #                   fe80::da67:d9ff:fe0a:4bc3  
    #Ethernet3/48       fe80::da67:d9ff:fe0a:4bc3  1         no
    #                   fe80::da67:d9ff:fe0a:4bc3  
    #Vlan10             fe80::da67:d9ff:fe0a:4bc3  1         no
    #                   fe80::da67:d9ff:fe0a:4bc3  
    #
    #Returned dictionary:
    #OrderedDict([('Ethernet3/47', OrderedDict([('IPv6_Address', 'fe80::da67:d9ff:fe0a:4bc3'), ('Neighbor_Count', '0'), ('Border_Interface', 'no'), ('PIM6_DR_Address', 'fe80::da67:d9ff:fe0a:4bc3')])), ('Ethernet3/48', OrderedDict([('IPv6_Address', 'fe80::da67:d9ff:fe0a:4bc3'), ('Neighbor_Count', '1'), ('Border_Interface', 'no'), ('PIM6_DR_Address', 'fe80::da67:d9ff:fe0a:4bc3')])), ('Vlan10', OrderedDict([('IPv6_Address', 'fe80::da67:d9ff:fe0a:4bc3'), ('Neighbor_Count', '1'), ('Border_Interface', 'no'), ('PIM6_DR_Address', 'fe80::da67:d9ff:fe0a:4bc3')]))])

    msg='Fetch pim6 interface info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    count='[0-9]+'
    border='yes|no'
    pim6_dict={}
    sw_cmd='show ipv6 pim interface brief'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getPim6InterfaceDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    eol='[ \t\r\n]+'
    pattern='({0}) +({1}) +({2}) +({3}){4}({1})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS,count,border,eol)
    interface_list=re.findall(pattern,output,re.I)
    if (len(interface_list)):
        pim6_dict=convertListToDict(interface_list,['Interface','IPv6_Address','Neighbor_Count','Border_Interface','PIM6_DR_Address'],'Interface')

    return pim6_dict

def getPim6NeighborDict(hdl,log,*args):

    #Returns the dictionary of pim6 neighbor info
    #(Neighbor's link local address, Interface) is key
    #uptime, expires, dr-priority, bidir are the second level keys
    #e.g.
    #Neighbor Address              Interface     Uptime    Expires   DR   Bidir
    #                                                                Pri
    #fe80::200:42ff:fe96:4fc8      Eth3/48       19:40:09  00:01:43  0    no
    #  no secondary addresses
    #fe80::200:42ff:fe96:4fc6      Vlan10        19:40:09  00:01:43  0    no
    #  no secondary addresses
    #
    #Returned dictionary:
    #{('fe80:0000:0000:0000:0200:42ff:fe96:4fc8', 'Eth3/48'): {'Bidir': 'no', 'Uptime': '19:40:09', 'Expires': '00:01:43', 'Dr_Pri': '0'}, ('fe80:0000:0000:0000:0200:42ff:fe96:4fc6', 'Vlan10'): {'Bidir': 'no', 'Uptime': '19:40:09', 'Expires': '00:01:43', 'Dr_Pri': '0'}}

    msg='Fetch pim6 neighbor info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['neighbor']='-type str'
    arggrammer['interface']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    priority='[0-9]+'
    bidir='yes|no'
    neighbor_dict={}
    sw_cmd='show ipv6 pim neighbor'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getPim6NeighborDict"
         print (msg)
         log.info(msg)
         return {}
    if ns.neighbor and ns.interface:
        msg='Invalid arguments in method:getPim6NeighborDict:-neighbor & -interface are exclusive'
        print (msg)
        log.info(msg)
        return {}
    if ns.neighbor:
        sw_cmd+=' '+ns.neighbor
    if ns.interface:
        sw_cmd+=' '+ns.interface    
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    
    pattern='({0}) +({1}) +({2}) +({3}) +({4}) +({5})'.format(rex.IP_ADDRESS,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME,priority,bidir)
    neighbor_list=re.findall(pattern,output,re.I)
    for nei in neighbor_list:
        ipv6_full=ipaddr.IPv6Address(nei[0]).exploded
        int=normalizeInterfaceName(log,nei[1])
        tmp={(ipv6_full,int):{'Uptime':nei[2],'Expires':nei[3],'Dr_Pri':nei[4],'Bidir':nei[5]}}
        neighbor_dict.update(tmp)

    return neighbor_dict

def getPim6NeighborCount(hdl,log,*args):

    #Returns the count of pim6 neighbors

    msg='Fetch pim6 neighbor count on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['neighbor']='-type str'
    arggrammer['interface']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    priority='[0-9]+'
    bidir='yes|no'
    neighbor_dict={}
    sw_cmd='show ipv6 pim neighbor'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getPim6NeighborCount"
         print (msg)
         log.info(msg)
         return 0
    if ns.neighbor and ns.interface:
        msg='Invalid arguments in method:getPim6NeighborCount:-neighbor & -interface are exclusive'
        print (msg)
        log.info(msg)
        return 0
    if ns.neighbor:
        sw_cmd+=' '+ns.neighbor
    if ns.interface:
        sw_cmd+=' '+ns.interface    
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    
    pattern='({0}) +({1}) +({2}) +({3}) +({4}) +({5})'.format(rex.IP_ADDRESS,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME,priority,bidir)
    neighbor_list=re.findall(pattern,output,re.I)
    return len(neighbor_list)


def getMroute6CountDict(hdl,log,*args):
    #Returns the dictionary of ipv6 mroute count info
    #e.g.
    #Total number of routes: 4
    #Total number of (*,G) routes: 1
    #Total number of (S,G) routes: 2
    #Total number of (*,G-prefix) routes: 1
    #Group count: 3, rough average sources per group: 0.6
    #Returned Dictionary:
    #{'(*,G)_routes': '1', 'group_count': '3', 'source_per_group': '0.6', '(*,G-prefix)_routes': '1', 'Total': '4', '(S,G)_routes': '2'}


    msg='Fetch ipv6 mroute count info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    mroute6_dict={}
    sw_cmd='show ipv6 mroute summary count'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getMroute6CountDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    if (re.search('Total number of routes: +([0-9]+)',output,re.I)):
        mroute6_dict={'Total':re.search('Total number of routes: +([0-9]+)',output,re.I).group(1)}
    if (re.search('Total number of \(\*,G\) routes: +([0-9]+)',output,re.I)):
        tmp={'(*,G)_routes':re.search('Total number of \(\*,G\) routes: +([0-9]+)',output,re.I).group(1)}
        mroute6_dict.update(tmp)
    if (re.search('Total number of \(S,G\) routes: +([0-9]+)',output,re.I)):
        tmp={'(S,G)_routes':re.search('Total number of \(S,G\) routes: +([0-9]+)',output,re.I).group(1)}
        mroute6_dict.update(tmp)
    if (re.search('Total number of \(\*,G-prefix\) routes: +([0-9]+)',output,re.I)):
        tmp={'(*,G-prefix)_routes':\
                re.search('Total number of \(\*,G-prefix\) routes: +([0-9]+)',output,re.I).group(1)}
        mroute6_dict.update(tmp)
    if (re.search('Group count: +([0-9]+)',output,re.I)):
        tmp={'group_count':re.search('Group count: +([0-9]+)',output,re.I).group(1)}
        mroute6_dict.update(tmp)
    if (re.search('rough average sources per group: +([0-9]+(\.[0-9]+)?)',output,re.I)):
        tmp={'source_per_group':re.search('rough average sources per group: +([0-9]+(\.[0-9]+)?)',\
                                             output,re.I).group(1)}
        mroute6_dict.update(tmp)

    return mroute6_dict

def getMroute6Dict(hdl,log,*args):

    #Returns the dictionary of ipv6 mroute info
    #(source,group) is key
    #e.g.
    #(*, ff03::1/64), uptime: 1d10h, pim6 ipv6 
    #  Incoming interface: Null, RPF nbr: 0::
    #  Outgoing interface list: (count: 0)
    #
    #(2048::2/128, ff03::/128), uptime: 03:06:06, mld pim6 ipv6 
    #  Incoming interface: Ethernet3/48, RPF nbr: 2048::2
    #  Outgoing interface list: (count: 1)
    #    Ethernet3/48, uptime: 03:06:06, mld, (RPF)
    #
    #(*, ff04::/128), uptime: 1d10h, pim6 mld ipv6 
    #  Incoming interface: Null, RPF nbr: 0::
    #  Outgoing interface list: (count: 2)
    #    Vlan10, uptime: 03:05:21, mld
    #    Ethernet3/47, uptime: 03:06:07, mld
    #
    #
    #Returned Dictionary:
    #{('*', 'ff04:0000:0000:0000:0000:0000:0000:0000'): {'RPF_nbr': '0::', 'oif_list': ['Vlan10', 'Eth3/47'], 'uptime': '1d10h', 'rpf_interface': 'Null', 'oif_count': '2'}, ('*', 'ff03:0000:0000:0000:0000:0000:0000:0001'): {'RPF_nbr': '0::', 'oif_list': [], 'uptime': '1d10h', 'rpf_interface': 'Null', 'oif_count': '0'}, ('2048:0000:0000:0000:0000:0000:0000:0002', 'ff03:0000:0000:0000:0000:0000:0000:0000'): {'RPF_nbr': '2048::2', 'oif_list': ['Eth3/48'], 'uptime': '03:06:06', 'rpf_interface': 'Eth3/48', 'oif_count': '1'}}

    msg='Fetch ipv6 mroute info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['group']='-type str'
    arggrammer['source']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
    
    owner='static|ipv6|pim6|mld|m6rib'
    mroute6_dict={}
    sw_cmd='show ipv6 mroute'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getMroute6Dict"
         print (msg)
         log.info(msg)
         return {}
    if (ns.source and not ns.group):
         msg="Invalid arguments in method-getMroute6Dict:-source should be used together with -group"
         print (msg)
         log.info(msg)
         return {}
    if ns.group:
        sw_cmd+=' '+ns.group
    if ns.source:
        sw_cmd+=' '+ns.source
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    #split output with an empty new line 
    output_list=output.split('\r\n\r\n')
   
    for group_entry in output_list:
        found=0
        group_list=group_entry.splitlines()
        oif_list=[]
        #Parse a (*,g)/(s,g) group entry
        for line in group_list:
            #(*,g) entry 
            match=re.search('\(*, +({0})\/[0-9]+\), +uptime: ({1}), +(?:{2})'.format(rex.IP_ADDRESS,rex.UPTIME,owner),line,re.I)
            if match:
                src_addr='*'
                grp_addr=match.group(1)
                up_time=match.group(2)
                found=1
            #(s,g) entry
            if re.search('\(({0})\/128, +({0})\/128\), +uptime: ({1}), +(?:{2})'.format(rex.IP_ADDRESS,rex.UPTIME,owner),line,re.I):
                match=re.search('\(({0})\/128, +({0})\/128\), +uptime: ({1}), +(?:{2})'.format(rex.IP_ADDRESS,rex.UPTIME,owner),line,re.I)
                src_addr=match.group(1)
                grp_addr=match.group(2)
                up_time=match.group(3)
                found=1
            #iif info
            elif re.search('Incoming interface: +({0}), +RPF nbr: +({1})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS),line,re.I):
                match=re.search('Incoming interface: +({0}), +RPF nbr: +({1})'.format(rex.INTERFACE_NAME,rex.IP_ADDRESS),line,re.I)
                rpf_int=match.group(1)
                rpf_nbr=match.group(2)
            #oif count
            elif re.search('Outgoing interface list: +\(count: +([0-9]+)\)',line,re.I):
                match=re.search('Outgoing interface list: +\(count: +([0-9]+)\)',line,re.I)
                oif_cnt=match.group(1)
            #oif list info 
            elif re.search('({0}), +uptime: (?:{1}), +(?:{2})'.format(rex.INTERFACE_NAME,rex.UPTIME,owner),line,re.I):
                match=re.search('({0}), +uptime: (?:{1}), +(?:{2})'.format(rex.INTERFACE_NAME,rex.UPTIME,owner),line,re.I)
                oif=match.group(1)
                oif_list.append(oif)
        #Add each group entry to dictionary
        if (found):
            #Normalize ipv6 address and interface name in RPF and oif-list
            if src_addr!='*':
                src_addr=ipaddr.IPv6Address(src_addr).exploded
            grp_addr=ipaddr.IPv6Address(grp_addr).exploded
            rpf_int=normalizeInterfaceName(log,rpf_int)
            oif_list=normalizeInterfaceName(log,oif_list)
            tmp={(src_addr,grp_addr):{'uptime':up_time,'rpf_interface':rpf_int,'RPF_nbr':rpf_nbr,'oif_count':oif_cnt,'oif_list':oif_list}}
            mroute6_dict.update(tmp)
    return mroute6_dict

###########
def getRunningServicesDict (hdl,log, *args):

    """Return state of all services in Dict format
    Sample Usage:
    getRunningServicesDict (hdl, log)
    """
    cmd_out = hdl.execute ('show system internal sysmgr service running')
    pattern = '({0})\s+(0x{1})\s+({2})\s+({2})\s+s{1}\s+({2})\s+({0})\s+{2}'.format(rex.ALPHANUMSPECIAL,rex.HEX,rex.NUM)
    matchlist = re.findall(pattern,cmd_out)
    return convertListToDict(matchlist,['Name','UUID','PID','SAP','Start_Count','Tag'],['Name'])
        
#==================================================================================#
# loop_until - Method to loop until output of given function is verified against given value. 
# This function can be used in a verify-function to loop until a get-function passes with given value. 
#
# Mandatory Args
# funcname - name of function to be called
# funargs - Arguments to function (A tuple or list)
#        Fixed arguments, variable args, variable keyword args 
# expvalue - value to be verified against. It could be any type (int,str,tuple,list,dict) whatever relevant
#            to the get method
#
# Optional Args
# args - a string for additional arguments
#  -iteration - iteration of loops
#  -interval - interval between iterations
#  -negative - To invert pass/fail criteria
#
# Usage
# loop_until("eor_utils.getIgmpGroupcount",(hdl,log,'-vrf default'),3)
#
# value={'group_count': '2', 'source_per_group': '1.0', '(*,G)_routes': '2', 'Total': '3', '(S,G)_routes': '0', '(*,G-prefix)_routes': '1'}
# loop_until("eor_utils.getMrouteCountDict",(hdl,log,'-vrf default'), value)
#
# 
# loop_until("eor_utils.verifyVlans",(hdl,log,'-vlans 1,2,10-15',vlandict), expvalue)
#==================================================================================#
def loop_until(funcname,funcargs,expvalue,*args):


    arggrammar={}
    arggrammar['interval']='-type int -default 10'
    arggrammar['iterations']='-type int -default 3'
    arggrammar['negative']='-type bool'

    log=None
    for arg in funcargs:
        if re.search("Log",arg.__class__.__name__,flags=re.I):
            log = arg
            break

    if not log:
        print ("Logger object expected as one of the arguments")
        #raise Exception('SkipTestBlock From eor_utils')        
        return False

    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parseoutput.negative:
        parseoutput.negative='fail'
    else:
        parseoutput.negative='pass'

    if len(funcname.split(".")) == 1:
        module=sys.modules[__name__]
    else:
        module=sys.modules[funcname.split(".")[0]]
        funcname=funcname.split(".")[1]

    try:
        func = getattr(module, funcname)
    except AttributeError:
        log.info ('function not found \"{0}\" \({1}\)'.format(funcname, funcargs))
        return False

    argspec=inspect.getargspec(func)
    expectedarglen=len(argspec.args)
    actualarglen=len(funcargs)

    if actualarglen < expectedarglen:
        log.info ('Not enough arguments passed for {0} expected ({1} actual)'.format(funcname, argspec, funcargs))
        return False
   
    fixedargs=[]
    varargs=None
    keyworddict=None
    for i in range(expectedarglen):
        fixedargs.append(funcargs[i])
    fixedargs=tuple(fixedargs)
    if actualarglen > expectedarglen: 
        if argspec.keywords and re.search("dict",str(type(funcargs[actualarglen-1]))):
            keyworddict=funcargs[actualarglen-1]
            actualarglen=actualarglen-1
    if actualarglen > expectedarglen:
        varargs=tuple(funcargs[expectedarglen:actualarglen])
         
    for loop in range(parseoutput.iterations):
        if len(fixedargs):
            if varargs and keyworddict:
                # When fixedargs followed by unnamed variable args, then we need to explicitly
                # each fixed arg, hence this loop. If we come across a function needing
                # more than 12 fixed arguments followed by unnamed variable args, then this
                # code needs to be changed
                if len(fixedargs) == 1:
                    ret_value=func(fixedargs[0],*varargs,**keyworddict)
                elif len(fixedargs) == 2:
                    ret_value=func(fixedargs[0],fixedargs[1],*varargs,**keyworddict)
                elif len(fixedargs) == 3:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],*varargs,**keyworddict)
                elif len(fixedargs) == 4:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],*varargs,**keyworddict)
                elif len(fixedargs) == 5:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],*varargs,**keyworddict)
                elif len(fixedargs) == 6:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fxiedargs[3],fixedargs[4],fixedargs[5],*varargs,**keyworddict)
                elif len(fixedargs) == 7:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fxiedargs[4],fixedargs[5],fixedargs[6],\
                       *varargs,**keyworddict)
                elif len(fixedargs) == 8:
                    ret_value=func(fixedargs[0],fixedargs[1],fxiedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],*varargs,**keyworddict)
                elif len(fixedargs) == 9:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],fixedargs[8],*varargs,**keyworddict)
                elif len(fixedargs) == 10:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],fixedargs[8],fixedargs[9],*varargs,**keyworddict)
                elif len(fixedargs) == 11:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],fixedargs[8],fixedargs[9],fixedargs[10],*varargs,**keyworddict)
                elif len(fixedargs) == 12:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],fixedargs[8],fixedargs[9],fixedargs[10],fixedargs[11],*varargs,**keyworddict)
            elif varargs:
                if len(fixedargs) == 1:
                    ret_value=func(fixedargs[0],*varargs)
                elif len(fixedargs) == 2:
                    ret_value=func(fixedargs[0],fixedargs[1],*varargs)
                elif len(fixedargs) == 3:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],*varargs)
                elif len(fixedargs) == 4:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],*varargs)
                elif len(fixedargs) == 5:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],*varargs)
                elif len(fixedargs) == 6:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fxiedargs[3],fixedargs[4],fixedargs[5],*varargs)
                elif len(fixedargs) == 7:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fxiedargs[4],fixedargs[5],fixedargs[6],\
                       *varargs)
                elif len(fixedargs) == 8:
                    ret_value=func(fixedargs[0],fixedargs[1],fxiedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],*varargs)
                elif len(fixedargs) == 9:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],fixedargs[8],*varargs)
                elif len(fixedargs) == 10:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],fixedargs[8],fixedargs[9],*varargs)
                elif len(fixedargs) == 11:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],fixedargs[8],fixedargs[9],fixedargs[10],*varargs)
                elif len(fixedargs) == 12:
                    ret_value=func(fixedargs[0],fixedargs[1],fixedargs[2],fixedargs[3],fixedargs[4],fixedargs[5],fixedargs[6],\
                       fixedargs[7],fixedargs[8],fixedargs[9],fixedargs[10],fixedargs[11],*varargs)
            elif keyworddict:
                ret_value=func(*fixedargs,**keyworddict)
            else:
                ret_value=func(*fixedargs)
        else:
            if varargs and keyworddict:
                ret_value=func(*varargs,**keyworddict)
            elif varargs:
                ret_value=func(*varargs)
            elif keyworddict:
                ret_value=func(**keyworddict)
            else:
                ret_value=func()

        if re.search(parseoutput.negative,compareVars(expvalue,ret_value,log)):
            #testResult ('pass','Iteration {0}:function "{1}" passed'.format(loop,funcname),log)
            log.info ('Iteration {0}:function "{1}" passed'.format(loop,funcname))
            return True
        else:
            log.info ('Iteration {0}:function "{1}" did not pass. Expected:{2}, Actual:{3}'.format(loop,funcname,expvalue,ret_value))
            if loop<parseoutput.iterations-1:
                time.sleep(parseoutput.interval)
     

    #testResult ('fail','function "{0}" did not pass in all "{1}" iterations'.format(funcname,parseoutput.iterations),log)
    log.info('function "{0}" did not pass in all "{1}" iterations'.format(funcname,parseoutput.iterations))

    return False


######################################################################################
def getIpv4AclDict (hdl,log, *args):
    
    """Return All IP ACL details in dict format

    Sample Usage:
    getIpv4AclDict (hdl, log, '-acl_names test_acl')
    getIpv4AclDict (hdl, log,)
    """
    arggrammar={}
    arggrammar['acl_names']='-type str -default all_acls'
    argparse=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
 
    if (argparse.acl_names == 'all_acls'):
        cmd_out = hdl.execute ('show ip access-lists summary')
        pattern = 'IPV4 ACL\s+({0})'.format(rex.ALPHANUMSPECIAL)
        matchlist = re.findall(pattern,cmd_out)
        ACL_List = []
        system_acl_pattern = '(?:^\_LC.*\_$)|(?:^copp)'
        for item in matchlist:
            if not re.search(system_acl_pattern,item):
                ACL_List.append(item)
    else:
        ACL_List = argparse.acl_names.split(',')

    # Get acl_dict dictionary for ACLs in ACL_List
    pattern1 = 'Total ACEs Configured:\s+({0})'.format(rex.NUM)
    pattern2 = '({0})\s+\-\s+(ingress|egress)'.format(rex.INTERFACE_NAME)
    acl_dict = {}
    log.info('Get the details of each ACL name from the list:')
    for item in ACL_List:
        acl_summary = hdl.execute ('show ip access-list ' + item + ' summary')
        acl_summary_split = acl_summary.split('interfaces')
        match = re.search(pattern1,acl_summary_split[0])
        if match: 
            acl_dict[item] = {}
            acl_dict[item]['Total_ACEs'] = match.group(1)
            # Get ACL details of Configured ACL
            matchlist = re.findall(pattern2,acl_summary_split[1])
            matchlist2 = []
            for atuple in matchlist:
               tmp=normalizeInterfaceName(log,atuple[0])
               matchlist2.append([tmp,atuple[1]])
            acl_dict[item]['Configured'] = matchlist2
            # Get ACL details of Active ACL
            matchlist = re.findall(pattern2,acl_summary_split[2])
            matchlist2 = []
            for atuple in matchlist:
               tmp=normalizeInterfaceName(log,atuple[0])
               matchlist2.append([tmp,atuple[1]])
            acl_dict[item]['Active'] = matchlist2
            acl_output = hdl.execute ('show ip access-list ' + item)
            acl_output = re.sub('access list','access-list',acl_output)
            acl_dict[item]['ACL_Config'] = acl_output
    log.info('Return the final acl dictionary to calling function.')
    return acl_dict

# Added by sandesub
def getSpanningTreeBridgePriorityDict(hdl,log,*args):
    "getSpanningTreeBridgePriorityDict - returns a dict with vlan as key and configured bridge-priority and extended-bridge-priority as values. The extended bridge-priority is vlan_id + bridge-priority \
    mandatory args \
    hdl - switch handle object from icon \
    log - harness/python logging object \
    optional args\
    vlan \
    msti \
    Return format is a dict: {'vlan_id' : {'extended_bridge_priority' : 'ext_bp_val', 'bridge_priority' : 'bp_val'}\
    "
    arggrammar={}
    arggrammar['vlan']='-type str'
    arggrammar['msti']='-type str'
    arggrammar['mutualExclusive'] =[('vlan','msti')]
    stp_bp_dict = {}
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    if ns.vlan:
            command = "show spanning-tree vlan " + ns.vlan + " | grep Bridge | grep Priority"
    elif ns.msti:
            command = "show spanning-tree mst " + ns.msti + " | grep Bridge | grep priority"
    else:
            command = "show spanning-tree"
    output=hdl.execute(command)
    if ns.vlan:
        pattern = "Bridge ID[ \t]+Priority[ \t]+("+rex.NUM+")[ \t]+\(priority[ \t]+("+rex.NUM+")[ \t]+sys\-id\-ext[ \t]+("+rex.NUM+")"
        stp_bp_list=re.findall(pattern,output)
        stp_bp_dict=convertListToDict(stp_bp_list,['Extended_Bridge_Priority','Bridge_Priority','VLAN'],['VLAN'])
    if ns.msti:
        pattern = "Bridge[ \t]+address[ \t]+"+rex.MACADDR+"[ \t]+priority[ \t]+("+rex.NUM+")[ \t]+\(("+rex.NUM+")[ \t]+sysid[ \t]+("+rex.NUM+")"
        stp_bp_list=re.findall(pattern,output)
        stp_bp_dict=convertListToDict(stp_bp_list,['Extended_Bridge_Priority','Bridge_Priority','MSTI'],['MSTI'])
    return stp_bp_dict

# Added by sandesub
def getSpanningTreePortCostDict(hdl,log,*args):
    "getSpanningTreePortCostDict - returns a dict with vlan/msti as key and configured cost as values. \
    mandatory args \
    hdl - switch handle object from icon \
    log - harness/python logging object \
    optional args\
    intf \
    Return format is a dict: {'vlan_id' : {'cost' : '<cost_val>'}\
    Return format is a dict: {'msti' : {'cost' : '<cost_val>'}\
    "
    arggrammar={}
    arggrammar['intf']='-type str -required True'
    stp_cost_dict = {}
    stp_cost_dict_new = {}
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    if ns.intf:        
            command = "show spanning-tree interface " + ns.intf + " cost" 
    output=hdl.execute(command)
    mode = getSpanningTreeMode(hdl,log)

    if (mode=="rapid-pvst"):
        pattern = "VLAN([0-9]+)[ \t]+("+rex.NUM+")"
        stp_cost_list=re.findall(pattern,output)
        stp_cost_list_int = []
        stp_cost_list_str = []
        # convert the vlans into int format
        for (a,b) in stp_cost_list:
                stp_cost_list_int.append((int(a),b))
        # re-convert back into str
        for (a,b) in stp_cost_list_int:
                stp_cost_list_str.append((str(a),b))
        stp_cost_dict=convertListToDict(stp_cost_list_str,['VLAN','Cost'],['VLAN'])
        stp_cost_dict_new = addSubkeyToDict(stp_cost_dict,'Cost')

    if (mode=="mst"):
        pattern = "MST([0-9]+)[ \t]+("+rex.NUM+")"
        stp_cost_list=re.findall(pattern,output)
        stp_cost_list_int = []
        stp_cost_list_str = []
        # convert the vlans into int format
        for (a,b) in stp_cost_list:
                stp_cost_list_int.append((int(a),b))
        # re-convert back into str
        for (a,b) in stp_cost_list_int:
                stp_cost_list_str.append((str(a),b))
        stp_cost_dict=convertListToDict(stp_cost_list_str,['MSTI','Cost'],['MSTI'])
        stp_cost_dict_new = addSubkeyToDict(stp_cost_dict,'Cost')
    return stp_cost_dict_new

# Added by sandesub
def getSpanningTreePortPriorityDict(hdl,log,*args):
    "getSpanningTreePortPriorityDict - returns a dict with vlan/msti as key and configured port-priorities as values. \
    mandatory args \
    hdl - switch handle object from icon \
    log - harness/python logging object \
    optional args\
    intf \
    Return format is a dict: {'vlan_id' : {'Port_Priority' : '<cost_val>'}\
    Return format is a dict: {'msti' : {'Port_Priority' : '<cost_val>'}\
    "
    arggrammar={}
    arggrammar['intf']='-type str -required True'
    stp_cost_dict = {}
    stp_cost_dict_new = {}
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    if ns.intf:        
            command = "show spanning-tree interface " + ns.intf + " priority" 
    output=hdl.execute(command)
    mode = getSpanningTreeMode(hdl,log)

    if (mode=="rapid-pvst"):
        pattern = "VLAN([0-9]+)[ \t]+("+rex.NUM+")"
        stp_pp_list=re.findall(pattern,output)
        stp_pp_list_int = []
        stp_pp_list_str = []
        # convert the vlans into int format
        for (a,b) in stp_pp_list:
                stp_pp_list_int.append((int(a),b))
        # re-convert back into str
        for (a,b) in stp_pp_list_int:
                stp_pp_list_str.append((str(a),b))
        stp_pp_dict=convertListToDict(stp_pp_list_str,['VLAN','Port_Priority'],['VLAN'])
        stp_pp_dict_new = addSubkeyToDict(stp_pp_dict,'Port_Priority')

    if (mode=="mst"):
        pattern = "MST([0-9]+)[ \t]+("+rex.NUM+")"
        stp_pp_list=re.findall(pattern,output)
        stp_pp_list_int = []
        stp_pp_list_str = []
        # convert the vlans into int format
        for (a,b) in stp_pp_list:
                stp_pp_list_int.append((int(a),b))
        # re-convert back into str
        for (a,b) in stp_pp_list_int:
                stp_pp_list_str.append((str(a),b))
        stp_pp_dict=convertListToDict(stp_pp_list_str,['MSTI','Port_Priority'],['MSTI'])
        stp_pp_dict_new = addSubkeyToDict(stp_pp_dict,'Port_Priority')
    return stp_pp_dict_new

# Added by sandesub 
def addSubkeyToDict(input_dict,subkey):
        " This converts a dict of format {key : value} to format {key : {subkey : value}} "
        output_dict = {}
        for key in input_dict.keys():
                output_dict[key] = {subkey : input_dict[key]}
        return output_dict
        
# Added by sandesub            
def create2LevelDictIdentVal(key_range, subkey, value):
        " This is to create a dict with different keys having same subkey and same value for all keys \
        Returns a dict with elements of the key_range as key_values \
        Return format: {'k1' : {'subkey1' : value} , 'k2' : {'subkey1' : value} and so on...} \
        "
        key_list = strtoexpandedlist(key_range)
        dict = {}
        for i in range(len(key_list)):
                dict[key_list[i]] = {subkey : value}
        return dict

#Added by sandesub 
def createDictIdentVal(key_range, value):
        " This is to create a dict with different keys having same value for all keys \
        Return dict format: {'k1' : 'val1' , 'k2' : 'val1' ...} \
        "
        key_list = strtoexpandedlist(key_range)
        dict = {}
        for i in range(len(key_list)):
                dict[key_list[i]] = value
        return dict

# To get detail information of a fex such as Fabric ports etc
# Usage: getFexdetailDict(hdl,log) Will get all the fex modules which are online
# Usage: getFexdetailDict(hdl,log, '-fex 102,103')) will get only for the specific fex modules
#
# If Fabric_interface is a Po (which is the case most of the scenarios), then only Po
# will be included in the Fabric_interface & its members will be in ['Fabric_interface']['Po102']['Members']
# key
def getFexdetailDict(hdl,log,*args):

    arggrammar={}
    arggrammar['fex'] = '-type list -default "all"'

    parseoptions = parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if listtostr(parseoptions.fex) == 'all':
        showfexlist=hdl.execute("show fex detail | include FEX:")
        setattr(parseoptions,'fex',strtolist(str(re.findall("FEX:\s+([0-9]+)",showfexlist,flags=re.M)),True))

    returndict={}
    for fex in parseoptions.fex:
        showoutput=hdl.execute("show fex {0} detail".format(fex))
        if not re.search("FEX:\s+{0}".format(fex),showoutput):
            log.error("Fex {0} not found show output {1}".format(fex,showoutput))
        returndict[fex]={}
        findlist=re.findall("Description:\s+([A-Za-z0-9_]+)",showoutput)
        if len(findlist):
            returndict[fex]['Description']=findlist[0]
        findlist=re.findall("state:\s+([A-Za-z0-9_]+)",showoutput)
        if len(findlist):
            returndict[fex]['state']=findlist[0]
        findlist=re.findall("FEX version:\s+(\S+)",showoutput)
        if len(findlist):
            returndict[fex]['FEX_version']=findlist[0]
        findlist=re.findall("Switch version:\s+(\S+)",showoutput)
        if len(findlist):
            returndict[fex]['Switch_version']=findlist[0]
        findlist=re.findall("FEX Interim version:\s+(\S+)",showoutput)
        if len(findlist):
            returndict[fex]['FEX_Interim_version']=findlist[0]
        findlist=re.findall("Switch Interim version:\s+(\S+)",showoutput)
        if len(findlist):
            returndict[fex]['Switch_Interim_version']=findlist[0]
        findlist=re.findall("Extender Serial:\s+(\S+)",showoutput)
        if len(findlist):
            returndict[fex]['Extender_Serial']=findlist[0]
        findlist=re.findall("Extender Model:\s+(\S+)",showoutput)
        if len(findlist):
            returndict[fex]['Extender_Model']=findlist[0]
        findlist=re.findall("Part No:\s+([^,]+)",showoutput)
        if len(findlist):
            returndict[fex]['Part_No']=findlist[0]
        findlist=re.findall("Card Id:\s+([^,]+)",showoutput)
        if len(findlist):
            returndict[fex]['Card_Id']=findlist[0]
        findlist=re.findall("Mac Addr:\s+([^,]+)",showoutput)
        if len(findlist):
            returndict[fex]['Mac_Addr']=findlist[0]
        findlist=re.findall("Num Macs:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['Num_Macs']=findlist[0]
        findlist=re.findall("Module Sw Gen:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['Module_Sw_Gen']=findlist[0]
        findlist=re.findall("Switch Sw Gen:\s+([^\]]+)",showoutput)
        if len(findlist):
            returndict[fex]['Switch_Sw_Gen']=findlist[0]
        findlist=re.findall("post level:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['post_level']=findlist[0]
        findlist=re.findall("Pinning-mode:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['Pinning-mode']=findlist[0]
        findlist=re.findall("Max-links:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['Max_links']=findlist[0]
        findlist=re.findall("Fabric port for control traffic:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['Fabric_port_for_control_traffic']=normalizeInterfaceName(log,findlist[0])
        findlist=re.findall("FCoE Admin:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['FCoE_Admin']=findlist[0]
        findlist=re.findall("FCoE Oper:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['FCoE_Oper']=findlist[0]
        findlist=re.findall("FCoE FEX AA Configured:\s+([\S]+)",showoutput)
        if len(findlist):
            returndict[fex]['FCoE_FEX_AA_Configured']=findlist[0]
        findlist=re.findall("({0})\s+\-\s+Interface\s+([UpDown]+)\.\s+State:\s+([\S]+)".format(rex.INTERFACE_NAME),showoutput)
        if len(findlist):
            returndict[fex]['Fabric_interface']=convertListToDict(findlist,['interface','status','state'],['interface'])
        findlist=re.findall("({0})\s+([UpDown]+)\s+({0})".format(rex.INTERFACE_NAME),showoutput)
        if len(findlist):
            returndict[fex]['Fex_interfaces']=convertListToDict(findlist,['interface','State','Fabric_Port'],['interface'])

    for fex in returndict.keys():
        if 'Fabric_interface' in returndict[fex].keys():
            #final_fabric_interfaces=[]
            #fabric_interface_dict={}
            #fabric_interfaces=returndict[fex]['Fabric_interface'].keys()
            for interface in returndict[fex]['Fabric_interface'].keys():
                if re.search("^Po",interface):
                    #fabric_interface_dict[interface]=returndict[fex]['Fabric_interface'][interface]
                    members=getPortChannelMemberList( hdl,log, '-pc_nam {0}'.format(interface) )
                    normalizedMembers=[]
                    for member in members:
                        normalizedMembers.append(normalizeInterfaceName(log, member))
                    returndict[fex]['Fabric_interface'][interface]['Members']=normalizedMembers
                    #final_fabric_interfaces.append(interface)
                    #for member in normalizedMembers:
                    #    if member in fabric_interfaces:
                    #        final_fabric_interfaces.append(member)
                    #        fabric_interface_dict[interface]['Members'][member]=returndict[fex]['Fabric_interface'][member]
            #for interface in fabric_interfaces:
            #    if interface not in final_fabric_interfaces:
            #        fabric_interface_dict[interface]=returndict[fex]['Fabric_interface'][interface]
            #returndict[fex]['Fabric_interface']=fabric_interface_dict

    return returndict

# Inherting thread object to be able to run any function as a separate thread        
class eorThread (threading.Thread):
    def __init__(self,function,name,obj,*args):
        #print 'RECEIVED ARGS is: {0}'.format(args)
        threading.Thread.__init__(self,target=function,name=name,args=args,kwargs={})
        self._return=None
        self.obj=obj
    def run(self):
        #print 'INSIDE RUN'
        if self._Thread__target is not None:
            #print 'FINAL ARGS:'
            #print self._Thread__args
            #print 'FINAL KWARGS:'
            #print self._Thread__kwargs
            if self.obj:
                self._return=self._Thread__target(self.obj,*self._Thread__args,**self._Thread__kwargs)
            else:
                self._return=self._Thread__target(*self._Thread__args,**self._Thread__kwargs)
    def join(self,timeout=None):
        #print 'INSIDE JOIN'
        threading.Thread.join(self,timeout)
        return self._return

runparallel_timeout=1200
def runparallel(*functions,**funcargs):
    '''To run multiple methods concurrently
       Example1:
           obj1=stimuli_lib.stimuliRestartSysmgrService(hdl1,log,'-services ntp')
           obj2=stimuli_lib.stimuliRestartSysmgrService(hdl2,log,'-services aaa')
           eor_utils.runparallel(obj1.action,obj2.action)
       Example2:
           Note: This example below is trying to cover all scenarios in one shot
           Say there are three functions with following definitions:
              def func1()            # no args
              def func2(arg1)        # one arg
              def func3(arg1,arg2)   # two args
              def func4(arg1,*arg)   # one mandatory arg and any number of optional args
           You can frame a dictionary of function arguments and call runparallel as below
           inputargs={\
             'func2':('functionb',)\           # input args for func2
             'func3':('function','c'),\        # input args for func3
             'func4':('function','d','etc')\   # input args for func4
           }

           retval_dict=eor_utils.runparallel(func1,func2,func3,args_dict=inputargs)
         
           The return value is also a dictionary of the following form:
           retval_dict={\
             'func1': None\          # return value for func1
             'func2': 'xyz',\        # return value for func2
             'func3': [1,2,3],\      # return value for func3
             'func4': {'b':'lah'}\   # return value for func4
           }
       Example3:
           In case you want to run same function in parallel but with different arguments
           You will need to make a clone of the function using types.FunctionType (see sample
           in basic_sanity). Then use a unique name to identify the thread.
           Say there are three functions with following definitions:
              def func5(arg1,arg2)   # two args
           You can frame a dictionary of function arguments and call runparallel as below
           inputargs={\
             ('tmpFunc1','name1'):('func','51'),\  # input args for tmpFunc1 (a clone of func5)
             ('tmpFunc2','name2'):('func','52')\   # input args for tmpFunc2 (a clone of func5)
           }

           retval_dict=eor_utils.runparallel(tmpFunc1,tmpFunc2,args_dict=inputargs)
         
           The return value is also a dictionary of the following form:
           retval_dict={\
             'name1': None\          # return value for tmpFunc1 (a clone of func5)
             'name2': 'xyz',\        # return value for tmpFunc1 (a clone of func5)
           }
       Example3a:
           In case of cloning class methods, the clone is not a bound method anymore. Hence
           the object is not passed as 'self' automatically. So, you will need to pass the object
           explicitly. (see sample in basic_sanity)
           Say there are three functions with following definitions:
              def func5(arg1,arg2)   # two args
           You can frame a dictionary of function arguments and call runparallel as below
           inputargs={\
             ('tmpFunc1','name1',obj1):('func','51'),\  # input args for tmpFunc1 (a clone of func5)
             ('tmpFunc2','name2',obj2):('func','52')\   # input args for tmpFunc2 (a clone of func5)
           }
           'obj1' and 'obj2' are explicitly passed to the cloned method in lieu of 'self'
    '''
    #TODO a mechanism for passing kwargs to parallel procs (hint: pass as dict where keys are named variables)
    #TODO a mechanism for pass timeout, instead of the global runparallel_timeout

    if not functions:
        print('No functions to run')
        return

    # Having unique functions
    functions=list(set(list(functions)))

    args_dict=funcargs.get('args_dict',{})

    timeout=runparallel_timeout

    threads=[]
    for fn in functions:
        print('FN is {0}'.format(fn))
        fn_added=False
        for key in args_dict:
            obj=None
            #print 'KEY is {0}'.format(key)
            if type(key) is tuple:
                #print 'KEY is tuple'
                fnname=key[0]
                alias=key[1]
                if len(key)==3:
                    obj=key[2]
            else:
                #print 'KEY is NOT TUPLE {0}'.format(key)
                fnname=key
                alias=str(fnname)
            #print 'FNNAME IN KEY: {0}'.format(fnname)
            #print 'FN           : {0}'.format(fn)
            if fn == fnname:
                #print 'FN and FNNAME IN KEY are same'
                args=args_dict[key]
                if type(args) is not tuple:
                    print('funcargs are not in proper format. Elements HAVE to be tuple')
                    return
                #print 'SENDING ARGS is: {0}'.format(args)
                thread=eorThread(fn,alias,obj,*args)
                fn_added=True
                break
        if not fn_added:
            #print 'FN {0} NOT ADDED. No matching KEY'.format(fn)
            thread=eorThread(fn,fn.__name__,None)
        threads.append(thread)
        #time.sleep(2)

    for thread in threads:
        thread.start()

    return_dict={}
    for thread,fn in zip(threads,functions):
        retval=thread.join(timeout)
        alias=str(thread.getName())
        if alias==str(fn):
            alias=fn.__name__
        if thread.isAlive():
            # TODO figure out how to kill all threads
            print('{0} did not finish in {1} seconds'.format(alias,timeout))
            return {}
        return_dict.update({alias : retval})
    return return_dict
 

def getModuleList(hdl, log, *args):
    '''Returns list of slot numbers of online modules(sup,lc,fc,sc).

    Usage:
     fex_list=getModuleList(hdl,log)
     fex_list=getModuleList(hdl,log,'-type lc') # slot IDs of linecards only
     fex_list=getModuleList(hdl,log,'-model N7K-F248XP-25') # slot IDs of a particular model
     fex_list=getModuleList(hdl,log,'-state powered-dn') # slot IDs of modules in particular state'''

    arggrammar={}
    arggrammar['type']='-type str -choices ["lc","fc","sc","sup","non-sup","all"] -default all'
    arggrammar['model']='-type str -default all'
    arggrammar['modules']='-type str -format [0-9, ]+|all -default all'
    arggrammar['state']='-type str -choices ["online","ok","powered-dn","powered-up","testing",\
        "initializing","pwr-cycld","active","ha-standby","failure","inserted","all"] -default ok'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return []

    model=options_namespace.model
    state=options_namespace.state
    modules=options_namespace.modules
    module_type=options_namespace.type

    # In case user explicitly chooses the state 'ok', then also check for online states of sup
    # Allowing special case usage of the state 'online' also to mean same as state 'ok'
    if state=='ok' or state=='online':
        state='(?:ok|active|ha-standby|standby)'
    if state=='all':
        state='.*'

    command='show module'

    if model!='all':
        command+=' | grep {0}'.format(model)

    if hdl.device_type in ['EOR','sTOR']:
        # The code names here are only to support old 16-slot chassis
        # New chassis dont need this but wont harm having them here
        if module_type!='all':
            if module_type=='sup':
                command+=' | grep -i \"sup\\|kirkwood\"'
            if module_type=='fc':
                command+=' | grep -i \"fm\\|shasta\\|sierra\"'
            if module_type=='non-sup':
                command+=' | grep -i -v sup | grep -i -v kirkwood'
            if module_type=='lc':
                command+=' | grep -i \"lc\\|snowbird\\|seymour\"'
            if module_type=='sc':
                command+=' | grep -i \"sc\\|alta\"'
    else:
        # N7K and N5K
        if module_type!='fc' and module_type!='non-sup':
            command+=' | grep -i -v fabric'
        if module_type!='all':
            if module_type=='sup':
                command+=' | grep -i sup'
            if module_type=='fc':
                # If fc isnt supported same way as lc/sc then will need to revisit this
                command+=' | grep -i fabric'
            if module_type=='non-sup':
                command+=' | grep -i -v sup'
            if module_type=='lc':
                command+=' | grep -i module | grep -i -v fabric | grep -i -v sup'
            if module_type=='sc':
                command+=' | grep -i controller'

    show_output=hdl.execute(command)
    module_list=re.findall('^([0-9]+)[ \t]+[0-9]+[ \t]+(?:.*)[ \t]+[^\s]+[ \t]+{0}'.format(state),\
        show_output,re.M | re.I)

    if modules!='all':
        modules=re.split('[ ,]+',modules)
        temp_module_list=deepcopy(module_list)
        popped=0
        for index,module in enumerate(temp_module_list):
            if module not in modules:
                module_list.pop(index-popped) 
                popped+=1

    return list(set(module_list))


def getProcessesMemoryDict(hdl, log, *args):
    '''Returns dictionary format of 'show processes memory' of active sup and standby(if present).

    In addition it can return similar output for other modules as specified
    Return null dictionary for modules that arent available

    Usage:
     proc_mem_dict=getProcessesMemoryDict(hdl,log)
     proc_mem_dict=getProcessesMemoryDict(hdl,log,'-module 3,4,5')
     proc_mem_dict=getProcessesMemoryDict(hdl,log,'-fex 101,102')
    
    Sample return value:
    ^^^^^^^^^^^^^^^^^^^^
    First level key is the slot number
    Second level key is the pid of the process (process name is not unique)

    3:       <--- slot number
      '2343': {MemAlloc: '5427200', MemLimit: '160904128', MemUsed: '66568192', Process: mtm}
      '2344': {MemAlloc: '8974336', MemLimit: '131535641', MemUsed: '66019328', Process: fib}
      '2345': {MemAlloc: '62181376', MemLimit: '667789900', MemUsed: '132059136', Process: aclqos}'''
    
    arggrammar={}
    arggrammar['module']='-type str -format [0-9,]+'
    arggrammar['fex']='-type str -format [0-9,]+'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    processes_memory={}

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return processes_memory

    command='show processes memory | no-more'
    device_list=[]

    if options_namespace.module:
        module=options_namespace.module
        for device_id in str.split(module,','):
            device_list.append((device_id,'module'))
    if options_namespace.fex:
        fex=options_namespace.fex
        for device_id in str.split(fex,','):
            device_list.append((device_id,'fex'))

    if hdl.device_type == 'sTOR':
        device_list=[('1','active')]
        #device_list=[('1','active'), ('1','module')]
    elif hdl.device_type == 'EOR':
        # List of supervisor slots
        for sup_state in ['active','standby']:
            device_id=getSupervisorSlotNumber(hdl,log,'-state ' + sup_state)
            if device_id==0:
                continue
            # If sup slot was passed as a module then overwrite it 
            # such that we can do proper checks for success of 'attach' command
            try:
                index=[dev[0] for dev in device_list].index(device_id)
            except:
                device_list.append((device_id,sup_state))
            else:
                device_list[index]=(device_id,sup_state)

    for device in device_list:
        device_id=int(device[0])
        device_type=device[1]
        processes_memory[device_id]={}

        if device_type=='active':
            show_output=hdl.execute(command)
        elif device_type=='standby':
            show_output=hdl.execute(command,'-{0}'.format(device_type))
        else:
            show_output=hdl.execute(command,'-{0} {1}'.format(device_type,device_id))

        if not show_output:
            log.warning('No output in slot {0} for command: show processes memory'.format(device_id))
            continue

        proc_details_list=re.findall(\
            '([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+[^ \t]+[ \t]+([^ \t\r\n]+)',\
            show_output,re.M)

        for proc_detail in proc_details_list:
            pid=proc_detail[0]
            mem_alloc=proc_detail[1]
            mem_limit=proc_detail[2]
            mem_used=proc_detail[3]
            proc_name=proc_detail[4]
            processes_memory[device_id][pid]={}
            processes_memory[device_id][pid]['Process']=proc_name
            processes_memory[device_id][pid]['MemAlloc']=mem_alloc
            processes_memory[device_id][pid]['MemLimit']=mem_limit
            processes_memory[device_id][pid]['MemUsed']=mem_used

        if not processes_memory[device_id]:
            processes_memory.pop(device_id,None)

    return processes_memory


def getMemStatsDetailDict(hdl, log, process, *args):
    '''Returns dictionary format of mem-stats detail of a process.

    Can be used to get mem-stats detail from modules other than active sup
    Return null dictionary if device is not available or if command fails

    Usage:
     mem_stats_dict=getMemStatsDetailDict(hdl,log,ethpm) # Get info from active sup only
     mem_stats_dict=getMemStatsDetailDict(hdl,log,ethpm,'-sup standby') # Get info from standby sup only
     mem_stats_dict=getMemStatsDetailDict(hdl,log,ethpm,'-module 3') # Get info from this module only
     mem_stats_dict=getMemStatsDetailDict(hdl,log,ethpm,'-fex 101') # Get info from this fex only
    
    Sample return value:
    ^^^^^^^^^^^^^^^^^^^^
    First level key is tuple of (struct_name,struct_num)
    Second level keys are the allocs and bytes info
    
    (ADB_MEM_adb_data_t, '12'): {allocs: '69', allocs_max: '69', bytes: '3036', bytes_max: '3036'}
    (ADB_MEM_adb_key_type_t, '1'): {allocs: '4', allocs_max: '4', bytes: '48', bytes_max: '48'}'''
    
    arggrammar={}
    arggrammar['sup']='-type str -choices ["active","standby"]'
    arggrammar['module']='-type int'
    arggrammar['fex']='-type int'
    arggrammar['mutualExclusive'] =[('sup','module','fex')]

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    mem_stats_dict={}

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return mem_stats_dict

    if hdl.device_type == 'sTOR':
        device_list=[('1','active'), ('1','module')]
    elif hdl.device_type == 'EOR':
        device=(-1,'invalid')
        if options_namespace.module:
            device=(options_namespace.module,'module')
            active_sup_id=getSupervisorSlotNumber(hdl,log,'-state active')
            if int(active_sup_id)==int(options_namespace.module):
                device=(options_namespace.module,'active')
        elif options_namespace.fex:
            device=(options_namespace.fex,'fex')
        elif options_namespace.sup:
            sup_state=options_namespace.sup
            device_id=getSupervisorSlotNumber(hdl,log,'-state ' + sup_state)
            if device_id != 0:
                device=(device_id,sup_state)
        else:
            device_id=getSupervisorSlotNumber(hdl,log,'-state active')
            device=(device_id,'active')

        device_list=[device]
    else:
        device_list=[('1','active')]

    for device_id,device_type in device_list:
        device_id=int(device_id)
        #device_type=device[1]
        #device_type='active'
        if device_id==-1:
            log.warning('Module does not exist')
            return mem_stats_dict

        # Refer to the commands and aliases in class memUtils
        if process in memUtils.alias_and_cmds:
            command=memUtils.alias_and_cmds[process]['cmd'] + ' | no-more'
            if device_type=='active':
                show_output=hdl.execute(command)
            elif device_type=='standby':
                show_output=hdl.execute(command,'-{0}'.format(device_type))
            else:
                show_output=hdl.execute(command,'-{0} {1}'.format(device_type,device_id))
        else:
            log.warning('Searching for valid memstats command for {0}'.format(process))
            command_found=False
            for command in memUtils.memstat_cmd_syntax:
                command=re.sub('process_name',process,command) + ' | no-more'
                if device_type=='active':
                    show_output=hdl.execute(command)
                elif device_type=='standby':
                    show_output=hdl.execute(command,'-{0}'.format(device_type))
                else:
                    show_output=hdl.execute(command,'-{0} {1}'.format(device_type,device_id))
                if not re.search('% Invalid command at \'\^\' marker\.',show_output):
                    log.warning('Found valid memstats command for process {0}'.format(process))
                    log.warning('Add new memstats command to alias_and_cmds: {0}'.format(command))
                    command_found=True
                    break
            if not command_found:
                log.warning('Could not get relevant memstats command for {0}'.format(process))
                return mem_stats_dict

        struct_list=re.findall(\
            '([0-9]+)[ \t]+([^ ]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)',show_output)

        if struct_list:
            # This means if we find a valid memstat output in sup modules, then we go with it
            break

    grand_match=''
    if show_output:
        grand_match=re.search('Grand total bytes:\s+\d+\s+\((\d+)k\)',show_output) 

    if not show_output or not struct_list:
        log.warning('No output in slot {0} for command: {1}'.format(device_id,command))
        return mem_stats_dict

    for struct in struct_list:
        struct_num=struct[0]
        struct_name=struct[1]
        allocs=struct[2]
        allocs_max=struct[3]
        bytes=struct[4]
        bytes_max=struct[4]
        # form unique struct-id
        struct_id=(struct_name,struct_num)
        mem_stats_dict[struct_id]=\
            {'allocs':allocs,'bytes':bytes,'allocs_max':allocs_max,'bytes_max':bytes_max}

    if grand_match:
        mem_stats_dict['GrandMem']=grand_match.group(1)

    return mem_stats_dict


class memUtils(object):
    '''Memory utils such as checkMemLeak checkMtsLeak etc.'''

    # Definitions
    # option1: Maintain a list of procs we are disinterested in
    # Advantage is that this list need not be maintained for any new proc added to the product 
    procs_of_disinterest_list=['aio/0', 'aio/1', 'aio/10', 'aio/11', 'aio/12', 'aio/13', 'aio/14',\
        'aio/15', 'aio/2', 'aio/3', 'aio/4', 'aio/5', 'aio/6', 'aio/7', 'aio/8', 'aio/9',\
        'bloggerd', 'bootvar', 'capability', 'cert_enroll', 'cisco', 'clk_mgr', 'clp_elam',\
        'clp_fwd', 'clp_l3', 'clp_mac', 'clp_xbar', 'cmond', 'confcheck', 'core-dmon',\
        'crdcfg_server', 'dcos-xinetd', 'device_test', 'events/0', 'events/1', 'events/10',\
        'events/11', 'events/12', 'events/13', 'events/14', 'events/15', 'events/2', 'events/3',\
        'events/4', 'events/5', 'events/6', 'events/7', 'events/8', 'events/9', 'evmc', 'evms',\
        'ExceptionLog', 'fs-daemon', 'getty', 'inband_kthread', 'in.dcos-telnetd', 'in.dcos-telnetd',\
        'in.dcos-telnetd', 'in.dcos-telnetd', 'init', 'ip_dummy', 'ipv6_dummy', 'kacpid',\
        'kacpi_notify', 'kauditd', 'kblockd/0', 'kblockd/1', 'kblockd/10', 'kblockd/11',\
        'kblockd/12', 'kblockd/13', 'kblockd/14', 'kblockd/15', 'kblockd/2', 'kblockd/3',\
        'kblockd/4', 'kblockd/5', 'kblockd/6', 'kblockd/7', 'kblockd/8', 'kblockd/9', 'khelper',\
        'khubd', 'kjournald', 'klogd', 'kseriod', 'ksoftirqd/0', 'ksoftirqd/1', 'ksoftirqd/10',\
        'ksoftirqd/11', 'ksoftirqd/12', 'ksoftirqd/13', 'ksoftirqd/14', 'ksoftirqd/15',\
        'ksoftirqd/2', 'ksoftirqd/3', 'ksoftirqd/4', 'ksoftirqd/5', 'ksoftirqd/6', 'ksoftirqd/7',\
        'ksoftirqd/8', 'ksoftirqd/9', 'kstriped', 'ksuspend_usbd', 'kswapd0', 'kswapd1', 'kthreadd',\
        'lit', 'lmgrd', 'lockd', 'login', 'login', 'login', 'login', 'ls-notify-mts-t', 'md3_raid1',\
        'md4_raid1', 'md5_raid1', 'md6_raid1', 'migration/0', 'migration/1', 'migration/10',\
        'migration/11', 'migration/12', 'migration/13', 'migration/14', 'migration/15',\
        'migration/2', 'migration/3', 'migration/4', 'migration/5', 'migration/6', 'migration/7',\
        'migration/8', 'migration/9', 'module', 'more', 'mping_server', 'mping-thread',\
        'mts-sync-thr', 'mvsh', 'nfsd', 'nfsiod', 'otm', 'pdflush', 'pfm_dummy', 'pfstat',\
        'pktmgr_dummy', 'pltfm_config', 'plugin', 'portmap', 'ps', 'psshelper', 'psshelper_gsvc',\
        'raid_monitor', 'redun_kthread', 'res_mgr', 'rpciod/0', 'rpciod/1', 'rpciod/10', 'rpciod/11',\
        'rpciod/12', 'rpciod/13', 'rpciod/14', 'rpciod/15', 'rpciod/2', 'rpciod/3', 'rpciod/4',\
        'rpciod/5', 'rpciod/6', 'rpciod/7', 'rpciod/8', 'rpciod/9', 'rpc.mountd', 'rpm', 'sac_usd',\
        'sal', 'scsi_eh_0', 'scsi_eh_1', 'scsi_eh_2', 'sctpt_rx_thr', 'sctpt_tx_thr', 'sdwrapd',\
        'sksd', 'smm', 'spm', 'sysinfo', 'syslogd', 'sysmgr', 'tcpudp_dummy', 'tftpd', 'ttyd', 'u2',\
        'usbhsd', 'usb-storage', 'usb-storage', 'usb-storage', 'usd_mts_kthread', 'vmm', 'vsh',\
        'vsh', 'vsh', 'vsh', 'vsh', 'vshd', 'watchdog/0', 'watchdog/1', 'watchdog/10', 'watchdog/11',\
        'watchdog/12', 'watchdog/13', 'watchdog/14', 'watchdog/15', 'watchdog/2', 'watchdog/3',\
        'watchdog/4', 'watchdog/5', 'watchdog/6', 'watchdog/7', 'watchdog/8', 'watchdog/9',\
        'wdpunch_thread', 'xbar', 'xbar_client', 'xbar_driver_usd', 'xinetd', 'xmlma']

    # option2: Maintain a list of procs we are interested in
    # Advantage is that this list can be short and avoid unnecessary time spent on other procs
    # Disdvantage is that this list needs to be maintained for any new proc added to the product 

    sup_procs_of_interest_list=['ExceptionLog', 'aaa', 'acllog', 'aclmgr', 'adjmgr', 'arp', 'ascii-cfg', 'bfd', 'bfd_app', 'bgp', 'bios_daemon', 'bloggerd', 'bootvar', 'callhome', 'capability', 'cardclient', 'cdp', 'cert_enroll', 'cfs', 'clis', 'clk_mgr', 'confcheck', 'copp', 'core-dmon', 'crdcfg_server', 'dcos-xinetd', 'device_test', 'dhcp_snoop', 'diag_port_lb', 'diagclient', 'diagmgr', 'echat', 'eigrp', 'eltm', 'epld_upgrade', 'eth_dstats', 'eth_port_channel', 'ethpm', 'evmc', 'evms', 'feature-mgr', 'fex', 'fs-daemon', 'glbp', 'hsrp_engine', 'icmpv6', 'ifmgr', 'igmp', 'installer', 'interface-vlan', 'ip_dummy', 'ipqosmgr', 'ipv6_dummy', 'isis', 'l2fm', 'l2pt', 'l3vm', 'lacp', 'lcdc3_syncpoint1', 'lcdc3_syncpoint2', 'lcdc3_syncpoint3', 'lcdc3_syncpoint4', 'lcdc3_syncpoint5', 'ldap', 'licmgr', 'lldp', 'lmgrd', 'm2rib', 'm6rib', 'mcastfwd', 'mcm', 'mfdm', 'module', 'monitor', 'monitorc', 'mping_server', 'mrib', 'msdp', 'mvsh', 'netstack', 'npacl', 'ntp', 'nve', 'obfl', 'oim', 'orib', 'ospf', 'ospfv3', 'otm', 'pfm_dummy', 'pfstat', 'pim', 'pim6', 'pixm_gl', 'pixm_vl', 'pixmc', 'pktmgr_dummy', 'platform', 'plog_sup', 'pltfm_config', 'plugin', 'poap', 'pong', 'port-profile', 'private-vlan', 'psshelper', 'psshelper_gsvc', 'radius', 'res_mgr', 'rip', 'rpm', 'sal', 'scheduler', 'sdwrapd', 'securityd', 'sensor', 'session-mgr', 'sksd', 'smm', 'snmpd', 'spm', 'statsclient', 'stp', 'sysinfo', 'syslogd', 'tacacs', 'tcpudp_dummy', 'tftpd', 'ttyd', 'tunnel', 'u2', 'u2rib', 'u6rib', 'udld', 'ufdm', 'urib', 'vbuilder', 'vdc_mgr', 'vlan_mgr', 'vmm', 'vntag_mgr', 'vpc', 'vrrp-cfg', 'vrrp-eng', 'vshd', 'vtp', 'xbar', 'xinetd', 'xmlma']
    # No memstats command found for these procs
    # ['ExceptionLog', 'acllog', 'bios_daemon', 'bloggerd', 'bootvar', 'confcheck', 'core-dmon', 'crdcfg_server', 'dcos-xinetd', 'device_test', 'diag_port_lb', 'diagclient', 'diagmgr', 'echat', 'epld_upgrade', 'evmc', 'evms', 'feature-mgr', 'fs-daemon', 'installer', 'lcdc3_syncpoint1', 'lcdc3_syncpoint2', 'lcdc3_syncpoint3', 'lcdc3_syncpoint4', 'lcdc3_syncpoint5', 'lmgrd', 'm6rib', 'mping_server', 'mrib', 'netstack', 'nve', 'obfl', 'pfm_dummy', 'pim6', 'pixm_gl', 'pixm_vl', 'platform', 'plog_sup', 'pong', 'psshelper', 'psshelper_gsvc', 'scheduler', 'sdwrapd', 'sensor', 'sysinfo', 'syslogd', 'tftpd', 'ttyd', 'u2rib', 'u6rib', 'urib', 'vbuilder', 'vdc_mgr', 'vntag_mgr', 'vrrp-cfg', 'vshd', 'xinetd', 'xmlma']

    mod_procs_of_interest_list=['MVDXN', 'PFMCLNT', 'aclqos', 'bcm56321', 'bcm_usd', 'bfdc', 'bios_daemon', 'bloggerd', 'capability', 'card_lcm', 'cardclient', 'crdcfg_server', 'device_test', 'diagclient', 'dt_helper', 'evmc', 'iftmc', 'ipfib', 'klm_bde', 'lcdc3_syncpoint1', 'lcdc3_syncpoint2', 'lcdc3_syncpoint3', 'lcdc3_syncpoint4', 'lcdc3_syncpoint5', 'monitorc', 'mping_server', 'mtm', 'mvsh', 'nsausd', 'obfl', 'parsetree', 'pixmc', 'plog', 'port_client', 'psshelper', 'psshelper_gsvc', 'sdwrapd', 'sensor', 'statsclient', 'sysinfo', 'vntagc', 'xbar_client']
    # No memstats command found for these procs
    # ['bcm56321', 'lcdc3_syncpoint2', 'device_test', 'device_test', 'bcm_usd', 'mping_server', 'crdcfg_server', 'plog', 'nsausd', 'dt_helper', 'psshelper', 'parsetree', 'sensor', 'bfdc', 'sysinfo', 'bloggerd', 'psshelper_gsvc', 'lcdc3_syncpoint5', 'lcdc3_syncpoint4', 'ipfib', 'lcdc3_syncpoint1', 'evmc', 'lcdc3_syncpoint3', 'klm_bde', 'MVDXN', 'card_lcm', 'diagclient', 'PFMCLNT', 'obfl', 'xbar_client', 'port_client', 'bios_daemon', 'sdwrapd']

    fex_procs_of_interest_list=['cdpd','ethpc','portola','princeton','satctrl','satsyslog','vic_proxy','woodside']

    # Essentially combination of all procs, minus duplicates, minus the ones that dont have memstats command
    procs_of_interest_list=['aaa', 'aclmgr', 'aclqos', 'adjmgr', 'arp', 'ascii-cfg', 'bfd', 'bfd_app', 'bgp', 'callhome', 'capability', 'cardclient', 'cdp', 'cdpd', 'cert_enroll', 'cfs', 'clis', 'clk_mgr', 'copp', 'dhcp_snoop', 'eigrp', 'eltm', 'eth_dstats', 'eth_port_channel', 'ethpc', 'ethpm', 'fex', 'glbp', 'hsrp_engine', 'icmpv6', 'ifmgr', 'iftmc', 'igmp', 'interface-vlan', 'ipfib', 'ip_dummy', 'ipqosmgr', 'ipv6_dummy', 'isis', 'l2fm', 'l2pt', 'l3vm', 'lacp', 'ldap', 'licmgr', 'lldp', 'm2rib', 'mcastfwd', 'mcm', 'mfdm', 'module', 'monitor', 'monitorc', 'msdp', 'mtm', 'mvsh', 'npacl', 'ntp', 'oim', 'orib', 'ospf', 'ospfv3', 'otm', 'pfstat', 'pim', 'pixmc', 'pktmgr_dummy', 'pltfm_config', 'plugin', 'poap', 'port-profile', 'portola', 'princeton', 'private-vlan', 'radius', 'res_mgr', 'rip', 'rpm', 'sal', 'satctrl', 'satsyslog', 'securityd', 'session-mgr', 'sksd', 'smm', 'snmpd', 'spm', 'statsclient', 'stp', 'tacacs', 'tcpudp_dummy', 'tunnel', 'u2', 'udld', 'ufdm', 'vic_proxy', 'vlan_mgr', 'vmm', 'vntagc', 'vpc', 'vrrp-eng', 'vtp', 'woodside', 'xbar']

    # TODO: For testing trials 
    #procs_of_interest_list=['ifmgr','ethpm','l3vm']
    #procs_of_interest_list=['ethpm']

    memleak_ignore_list=[]

    mtsleak_ignore_list=[]

    # alias may be useless data. Trim it down if needed
    alias_and_cmds={}
    alias_and_cmds['urib']={'alias': 'urib','cmd': 'show routing internal mem-stats detail'}
    alias_and_cmds['fwm']={'alias': 'fwm','cmd': 'show platform fwm mem-stats detail'}
    alias_and_cmds['nve_mgr']={'alias': 'nve_mgr','cmd': 'show nve internal mem-stats detail'}
    alias_and_cmds['aaa']={'alias': 'aaa', 'cmd': 'show system internal aaa mem-stats detail'}
    alias_and_cmds['aclmgr']={'alias': 'aclmgr', 'cmd': 'show system internal aclmgr memstat detail'}
    alias_and_cmds['aclqos']={'alias': 'aclqos', 'cmd': 'show system internal aclqos mem-stats detail'}
    alias_and_cmds['adjmgr']={'alias': 'adjmgr', 'cmd': 'show system internal adjmgr internal mem-stats detail'}
    alias_and_cmds['arp']={'alias': 'ip arp', 'cmd': 'show ip arp internal mem-stats detail'}
    alias_and_cmds['ascii-cfg']={'alias': 'ascii-cfg', 'cmd': 'show system internal ascii-cfg mem-stats detail'}
    alias_and_cmds['bfd']={'alias': 'bfd', 'cmd': 'show system internal bfd memstat detail'}
    alias_and_cmds['bfd_app']={'alias': 'bfd-app', 'cmd': 'show system internal bfd-app memstat details'}
    alias_and_cmds['bgp']={'alias': 'bgp', 'cmd': 'show bgp internal mem-stats detail'}
    alias_and_cmds['mplsfwd']={'alias': 'mplsfwd', 'cmd': 'show system internal mplsfwd mem-stats detail'}
    alias_and_cmds['mplsmgr']={'alias': 'mplsmgr', 'cmd': 'sh system internal mpls manager mem-stats detail'}
    alias_and_cmds['callhome']={'alias': 'callhome', 'cmd': 'show system internal callhome mem-stats detail'}
    alias_and_cmds['capability']={'alias': 'capability', 'cmd': 'show system internal capability mem-stats detail'}
    alias_and_cmds['cardclient']={'alias': 'cardclient', 'cmd': 'show system internal cardclient memory'}
    alias_and_cmds['cdp']={'alias': 'cdp', 'cmd': 'show cdp internal mem-stats detail'}
    alias_and_cmds['cdpd']={'alias': 'cdp', 'cmd': 'show cdp internal mem-stats detail'}
    alias_and_cmds['cert_enroll']={'alias': 'cert-enroll', 'cmd': 'show system internal cert-enroll mem-stats detail'}
    alias_and_cmds['cfs']={'alias': 'cfs', 'cmd': 'show cfs internal mem-stats detail'}
    alias_and_cmds['clis']={'alias': 'cli', 'cmd': 'show cli internal mem-stats detail'}
    alias_and_cmds['clk_mgr']={'alias': 'clk_mgr', 'cmd': 'show system internal clk_mgr mem-stats detail'}
    alias_and_cmds['copp']={'alias': 'copp', 'cmd': 'show system internal copp mem-stats detail'}
    alias_and_cmds['dhcp_snoop']={'alias': 'dhcp', 'cmd': 'show system internal dhcp mem-stats detail'}
    alias_and_cmds['eigrp']={'alias': 'ip eigrp', 'cmd': 'show ip eigrp internal mem-stats detail'}
    alias_and_cmds['eltm']={'alias': 'eltm', 'cmd': 'show system internal eltm mem-stats detail'}
    alias_and_cmds['eth_dstats']={'alias': 'dstats', 'cmd': 'show system internal dstats mem-stats detail'}
    alias_and_cmds['eth_port_channel']={'alias': 'port-channel', 'cmd': 'show port-channel internal mem-stats detail'}
    alias_and_cmds['ethpc']={'alias': 'ethpc', 'cmd': 'show platform software ethpc mem-stats detail'}
    alias_and_cmds['ethpm']={'alias': 'ethpm', 'cmd': 'show system internal ethpm mem-stats detail'}
    alias_and_cmds['evmc']={'alias': 'evmc', 'cmd': 'show event manager internal evmc mem-stats detail'}
    alias_and_cmds['evms']={'alias': 'evms', 'cmd': 'show event manager internal evms mem-stats detail'}
    alias_and_cmds['fex']={'alias': 'fex', 'cmd': 'show fex internal mem-stats detail'}
    alias_and_cmds['glbp']={'alias': 'glbp', 'cmd': 'show glbp internal mem-stats detail'}
    alias_and_cmds['hsrp_engine']={'alias': 'hsrp', 'cmd': 'show hsrp internal mem-stats detail'}
    alias_and_cmds['icmpv6']={'alias': 'icmpv6', 'cmd': 'show system internal icmpv6 internal mem-stats detail'}
    alias_and_cmds['ifmgr']={'alias': 'im', 'cmd': 'show system internal im mem-stats detail'}
    alias_and_cmds['iftmc']={'alias': 'iftmc', 'cmd': 'show system internal iftmc mem-stats detail'}
    alias_and_cmds['igmp']={'alias': 'ip igmp', 'cmd': 'show ip igmp internal mem-stats detail'}
    alias_and_cmds['interface-vlan']={'alias': 'interface-vlan', 'cmd': 'show system internal interface-vlan mem-stats detail'}
    alias_and_cmds['ip_dummy']={'alias': 'ip', 'cmd': 'show ip internal mem-stats detail'}
    alias_and_cmds['ipfib']={'alias': 'ipfib', 'cmd': 'show system internal ipfib mem-stats detail'}
    alias_and_cmds['ipqosmgr']={'alias': 'ipqos', 'cmd': 'show system internal ipqos mem-stats detail'}
    alias_and_cmds['ipv6_dummy']={'alias': 'ipv6', 'cmd': 'show ipv6 internal mem-stats detail'}
    alias_and_cmds['isis']={'alias': 'isis', 'cmd': 'show isis internal mem-stats detail'}
    alias_and_cmds['l2fm']={'alias': 'l2fm', 'cmd': 'show system internal l2fm mem-stats detail'}
    alias_and_cmds['l2pt']={'alias': 'l2pt', 'cmd': 'show system internal l2pt mem-stats detail'}
    alias_and_cmds['l3vm']={'alias': 'l3vm', 'cmd': 'show system internal l3vm mem-stats detail'}
    alias_and_cmds['lacp']={'alias': 'lacp', 'cmd': 'show lacp internal mem-stats detail'}
    alias_and_cmds['ldap']={'alias': 'ldap', 'cmd': 'show system internal ldap mem-stats detail'}
    alias_and_cmds['licmgr']={'alias': 'license', 'cmd': 'show system internal license mem-stats detail'}
    alias_and_cmds['lldp']={'alias': 'lldp', 'cmd': 'show system internal lldp mem-stats detail'}
    alias_and_cmds['m2rib']={'alias': 'm2rib', 'cmd': 'show system internal m2rib internal mem-stats detail'}
    alias_and_cmds['mcastfwd']={'alias': 'mfwd', 'cmd': 'show system internal mfwd mem-stats detail'}
    alias_and_cmds['mcm']={'alias': 'mcm', 'cmd': 'show system internal mcm mem-stats detail'}
    alias_and_cmds['mfdm']={'alias': 'mfdm', 'cmd': 'show system internal mfdm mem-stats detail'}
    alias_and_cmds['module']={'alias': 'module', 'cmd': 'show module internal mem-stats detail'}
    alias_and_cmds['monitor']={'alias': 'monitor', 'cmd': 'show monitor internal mem-stats detail'}
    alias_and_cmds['monitorc']={'alias': 'monitorc', 'cmd': 'show system internal monitorc mem-stats detail'}
    alias_and_cmds['msdp']={'alias': 'ip msdp', 'cmd': 'show ip msdp internal mem-stats detail'}
    alias_and_cmds['mtm']={'alias': 'mtm', 'cmd': 'show system internal mtm mem-stats detail'}
    alias_and_cmds['mvsh']={'alias': 'mvsh', 'cmd': 'show event manager internal mvsh mem-stats detail'}
    alias_and_cmds['npacl']={'alias': 'npacl', 'cmd': 'show system internal npacl mem-stats detail'}
    alias_and_cmds['ntp']={'alias': 'ntp', 'cmd': 'show ntp internal mem-stats detail'}
    alias_and_cmds['oim']={'alias': 'oim', 'cmd': 'show system internal oim mem-stats detail'}
    alias_and_cmds['orib']={'alias': 'orib', 'cmd': 'show system internal orib mem-stats detail'}
    alias_and_cmds['ospf']={'alias': 'ospf', 'cmd': 'show ospf internal mem-stats detail'}
    alias_and_cmds['ospfv3']={'alias': 'ospfv3', 'cmd': 'show ospfv3 internal mem-stats detail'}
    alias_and_cmds['otm']={'alias': 'track', 'cmd': 'show track internal mem-stats detail'}
    alias_and_cmds['pfstat']={'alias': 'pfstat', 'cmd': 'show system internal pfstat mem-stats detail'}
    alias_and_cmds['pim']={'alias': 'ip pim', 'cmd': 'show ip pim internal mem-stats detail'}
    alias_and_cmds['pixmc']={'alias': 'pixmc', 'cmd': 'show system internal pixmc mem-stats detail'}
    alias_and_cmds['pktmgr_dummy']={'alias': 'pktmgr', 'cmd': 'show system internal pktmgr internal mem-stats detail'}
    alias_and_cmds['pltfm_config']={'alias': 'pltfm_config', 'cmd': 'show system internal pltfm_config mem-stats detail'}
    alias_and_cmds['plugin']={'alias': 'plugin', 'cmd': 'show system internal plugin mem-stats detail'}
    alias_and_cmds['poap']={'alias': 'poap', 'cmd': 'show poap internal mem-stats detail'}
    alias_and_cmds['port-profile']={'alias': 'port-profile', 'cmd': 'show system internal port-profile mem-stats detail'}
    alias_and_cmds['portola']={'alias': 'portola', 'cmd': 'show platform software portola mem_stats detail'}
    alias_and_cmds['princeton']={'alias': 'princeton', 'cmd': 'show platform software princeton mem_stats detail'}
    alias_and_cmds['private-vlan']={'alias': 'private-vlan', 'cmd': 'show system internal private-vlan mem-stats detail'}
    alias_and_cmds['radius']={'alias': 'radius', 'cmd': 'show system internal radius mem-stats detail'}
    alias_and_cmds['res_mgr']={'alias': 'resource', 'cmd': 'show resource internal mem-stats detail'}
    alias_and_cmds['rip']={'alias': 'ip rip', 'cmd': 'show ip rip internal mem-stats detail'}
    alias_and_cmds['rpm']={'alias': 'rpm', 'cmd': 'show system internal rpm mem-stats detail'}
    alias_and_cmds['sal']={'alias': 'sal', 'cmd': 'show system internal sal mem-stats detail'}
    alias_and_cmds['satctrl']={'alias': 'satctrl', 'cmd': 'show platform software satctrl mem-stats detail'}
    alias_and_cmds['satsyslog']={'alias': 'satsyslog', 'cmd': 'show satsyslog internal mem-stats detail'}
    alias_and_cmds['securityd']={'alias': 'security', 'cmd': 'show system internal security mem-stats detail'}
    alias_and_cmds['session-mgr']={'alias': 'session-mgr', 'cmd': 'show system internal session-mgr mem-stats detail'}
    alias_and_cmds['sksd']={'alias': 'sksd', 'cmd': 'show system internal sksd mem-stats detail'}
    alias_and_cmds['smm']={'alias': 'smm', 'cmd': 'show system internal smm mem-stats shared detail'}
    alias_and_cmds['snmpd']={'alias': 'snmp', 'cmd': 'show system internal snmp mem-stats detail'}
    alias_and_cmds['spm']={'alias': 'spm', 'cmd': 'show system internal spm mem-stats detail'}
    alias_and_cmds['statsclient']={'alias': 'statsclient', 'cmd': 'show system internal statsclient memory'}
    alias_and_cmds['stp']={'alias': 'spanning-tree', 'cmd': 'show spanning-tree internal mem-stats detail'}
    alias_and_cmds['tacacs']={'alias': 'tacacs', 'cmd': 'show system internal tacacs mem-stats detail'}
    alias_and_cmds['tcpudp_dummy']={'alias': 'sockets', 'cmd': 'show sockets internal mem-stats detail'}
    alias_and_cmds['tunnel']={'alias': 'tunnel', 'cmd': 'show tunnel internal mem-stats detail'}
    alias_and_cmds['u2']={'alias': 'u2', 'cmd': 'show system internal u2 mem-stats detail'}
    alias_and_cmds['udld']={'alias': 'udld', 'cmd': 'show udld internal memory detail'}
    alias_and_cmds['ufdm']={'alias': 'ufdm', 'cmd': 'show system internal ufdm mem-stats detail'}
    alias_and_cmds['vic_proxy']={'alias': 'vic_proxy', 'cmd': 'show platform software vic_proxy mem-stats detail'}
    alias_and_cmds['vlan_mgr']={'alias': 'vlan', 'cmd': 'show vlan internal mem-stats detail'}
    alias_and_cmds['vmm']={'alias': 'vmm', 'cmd': 'show system internal vmm mem-stats detail'}
    alias_and_cmds['vntagc']={'alias': 'vntagc', 'cmd': 'show system internal vntagc mem-stats detail'}
    alias_and_cmds['vpc']={'alias': 'vpc', 'cmd': 'show system internal vpc mem-stats detail'}
    alias_and_cmds['vrrp-eng']={'alias': 'vrrp', 'cmd': 'show vrrp internal mem-stats detail'}
    alias_and_cmds['vtp']={'alias': 'vtp', 'cmd': 'show vtp internal mem-stats detail'}
    alias_and_cmds['woodside']={'alias': 'woodside', 'cmd': 'show platform software woodside mem_stats detail'}
    alias_and_cmds['xbar']={'alias': 'xbar', 'cmd': 'show system internal xbar mem-stats detail'}
    # this list will grow more...


    memstat_cmd_syntax=[\
        'show system internal process_name mem-stats detail',\
        'show system internal process_name memstat detail',\
        'show process_name internal mem-stats detail',\
        'show process_name internal memstat detail',\
        'show ip process_name internal mem-stats detail',\
        'show ipv6 process_name internal mem-stats detail',\
        'show platform software process_name mem-stats detail',\
        'show platform software process_name memstat detail',\
        'show platform software process_name internal mem-stats detail',\
        'show platform software process_name internal memstat detail',\
        'show platform process_name memstat detail',\
        'show platform process_name mem-stats detail',\
        'show system internal process_name memory'\
    ]

    memleak_threshold_dict={}
    memleak_threshold_dict['sup']={}
    memleak_threshold_dict['sup']['system_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['sup']['process_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['sup']['process_allocs']={'increments':5}
    memleak_threshold_dict['sup']['structure_allocs']={'increments':5}
    
    memleak_threshold_dict['lc']={}
    memleak_threshold_dict['lc']['system_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['lc']['process_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['lc']['process_allocs']={'increments':5}
    memleak_threshold_dict['lc']['structure_allocs']={'increments':5}
 
    memleak_threshold_dict['fc']={}
    memleak_threshold_dict['fc']['system_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['fc']['process_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['fc']['process_allocs']={'increments':5}
    memleak_threshold_dict['fc']['structure_allocs']={'increments':5}
 
    memleak_threshold_dict['sc']={}
    memleak_threshold_dict['sc']['system_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['sc']['process_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['sc']['process_allocs']={'increments':5}
    memleak_threshold_dict['sc']['structure_allocs']={'increments':5}
 
    memleak_threshold_dict['fex']={}
    memleak_threshold_dict['fex']['system_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['fex']['process_memory']={'percentage':2,'increments':5}
    memleak_threshold_dict['fex']['process_allocs']={'increments':5}
    memleak_threshold_dict['fex']['structure_allocs']={'increments':5}

    fdleak_threshold_dict={}
    fdleak_threshold_dict['total']=25

    # This is 1MB
    dfleak_threshold_dict={}
    dfleak_threshold_dict['Used']=1000

    # This is 1MB
    tmp_logs_leak_threshold_dict={}
    tmp_logs_leak_threshold_dict['Size']=1000

    # Green means things are good
    # Orange means a low priority resource has crossed threshold
    # Red means a high priority resource has crossed threshold
    green,orange,red,dead=0,1,2,3
    color=['green','orange','red']
 
    def __init__(self,hdl_list,log,*args):
        '''
        Usage:
          obj=memUtils(hdl_list,log)
          obj=memUtils(hdl_list,log,'-sup all') # get info for sup only
          obj=memUtils(hdl_list,log,'-fex all') # get info for all fex only
          obj=memUtils(hdl_list,log,'-fex none') # get info for all sup+modules only
          obj=memUtils(hdl_list,log,'-sup active') # get info for active sup only
          obj=memUtils(hdl_list,log,'-module 3,4') # get info for these modules only
          obj=memUtils(hdl_list,log,'-fex 101,102') # get info for these fex only
          obj=memUtils(hdl_list,log,'-process aaa') # get info for this process only
          obj=memUtils(hdl_list,log,'-memleak_ignore ['aaa','radius']') # ignore memleak for these'''

        self.alert=memUtils.green
        self.result='pass'

        if type(hdl_list) is not list:
            hdl_list=[hdl_list]

        self.hdl_list=hdl_list
        self.log=log

        arggrammar={}
        arggrammar['sup']='-type str -choices ["active","standby","all"]'
        arggrammar['module']='-type str -format [0-9,]+'
        arggrammar['fex']='-type str -format [0-9,]+|all|none'
        arggrammar['mutualExclusive'] =[('sup','module','fex')]
        arggrammar['process']='-type str -default all'
        arggrammar['memleak_ignore']='-type list -default []'

        options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

        if not options_namespace.VALIDARGS:
            self.log.warning('Invalid arguments')
            self.result='fail'
            return 

        self.memleak_ignore_list=deepcopy(memUtils.memleak_ignore_list)
        self.memleak_ignore_list.extend(options_namespace.memleak_ignore)

        self.memleak_threshold_dict=deepcopy(memUtils.memleak_threshold_dict)
        # TODO: Allow for user to override the thresholds

        self.mem_dict={}
        self.switch_ids={}
        self.device_list={}

        # TODO: later optimize this to use runParallel to save time
        for index,hdl in enumerate(self.hdl_list):
            # generate switch_ids
            cmd_output=hdl.execute('show sprom sup | grep Serial')
            result=re.search('Serial Number[ \t]+:[ \t]+([a-zA-Z0-9]+)',cmd_output)
            if result:
                serial_number=result.group(1)              
            else:
                serial_number='hdl#{0}'.format(index)
            # serial_number is just to keep it unique in case switchName isnt
            switch_id=(hdl.switchName,serial_number)
            self.switch_ids[switch_id]=hdl

            # Best to initialize everything here instead of doing it in the first call of checkMemLeak
            # Get list of online devices in each hdl
            device_list=[]
            if options_namespace.sup:
                sup=options_namespace.sup
                if hdl.device_type == 'sTOR':
                    device_id='1'
                    device_list.append(device_id)
                elif hdl.device_type == 'EOR':
                    if sup in ['active','standby']:
                        device_id=getSupervisorSlotNumber(hdl,self.log,'-state ' + sup)
                        device_list.append(device_id)
                    elif sup=='all':
                        device_list.extend(getModuleList(hdl,self.log,'-type sup'))
    
            # Note: These module numbers are same for all switches in the hdl_list
            if options_namespace.module:
                module=options_namespace.module
                device_list.extend(re.split('[ ,]+',module))
                online_list=getModuleList(hdl,log)
                if compareVars(device_list,online_list,self.log)=='fail':
                    self.log.error('Some modules in this list are not online: {0}'.format(device_list))
                    self.result='fail'
                    return
    
            if options_namespace.fex:
                fex=options_namespace.fex
                if fex=='all':
                    device_list.extend(getFexModuleList(hdl,self.log))
                elif fex=='none':
                    device_list.extend(getModuleList(hdl,self.log))
                else:
                    # Note: These fex numbers are same for all switches in the hdl_list
                    device_list.extend(re.split('[ ,]+',fex))
    
            # Default is, all modules in the system
            if not device_list:
                if hdl.device_type == 'sTOR':
                    device_id='1'
                    device_list.append(device_id)
                elif hdl.device_type == 'EOR':
                    device_list.extend(getModuleList(hdl,log))
                device_list.extend(getFexModuleList(hdl,self.log))

            device_list=sorted(map(int,device_list))
            module_ids=','.join(map(str,device_list[:bisect.bisect_left(device_list,100)]))
            fex_ids=','.join(map(str,device_list[bisect.bisect_left(device_list,100):]))
            devices=''
            if module_ids:
                devices+='-module ' + module_ids
            if fex_ids:
                devices+=' -fex ' + fex_ids
            #device_list=map(str,device_list)

            self.device_list[switch_id]=device_list

            system_resources_dict=getSystemResourcesDict(hdl,self.log,devices)
            process_memory_dict=getProcessesMemoryDict(hdl,self.log,devices)

            self.mem_dict[switch_id]={}
            for device_id in device_list:

                # Skipping FEXs for now since commands dont work on it
                if device_id >= 100:
                    continue

                self.mem_dict[switch_id][device_id]={}

                # gather system memory info
                self.mem_dict[switch_id][device_id]['system_memory']={}
                try:
                    used_mem=re.search('([0-9]+)',\
                        system_resources_dict[device_id]['Memory usage']['used']).group(1)
                except:
                    # The right thing to do here is probably fail the case
                    testResult('fail','Did not find system memory info for {0} module {1}'\
                        .format(switch_id,device_id),self.log)
                    used_mem='0'
                self.mem_dict[switch_id][device_id]['system_memory']['MemUsed']=[used_mem]
                self.mem_dict[switch_id][device_id]['system_memory']['increments']=0

                # gather process memory info
                self.mem_dict[switch_id][device_id]['process_memory']={}
                if device_id not in process_memory_dict or not process_memory_dict[device_id]:
                    # The right thing to do here is probably fail the case
                    testResult('fail','Did not find process memory info for {0} module {1}'\
                        .format(switch_id,device_id),self.log)
                    process_memory_dict[device_id]={}
                for pid in process_memory_dict[device_id].keys():
                    proc_name=process_memory_dict[device_id][pid]['Process']
                    if proc_name not in memUtils.procs_of_interest_list:
                        continue
                    # skip processes of disinterest
                    #if proc_name in memUtils.procs_of_disinterest_list:
                    #    continue
                    # skip processes in ignore list
                    if proc_name in self.memleak_ignore_list:
                        continue
                    # keep process_id unique with this combo
                    process_id=(pid,proc_name)
                    self.mem_dict[switch_id][device_id]['process_memory'][process_id]={}
                    self.mem_dict[switch_id][device_id]['process_memory']\
                        [process_id]['MemUsed']=[process_memory_dict[device_id][pid]['MemUsed']]
                    self.mem_dict[switch_id][device_id]['process_memory']\
                        [process_id]['MemUsedIncrements']=0
                    self.mem_dict[switch_id][device_id]['process_memory']\
                        [process_id]['MemAlloc']=[process_memory_dict[device_id][pid]['MemAlloc']]
                    self.mem_dict[switch_id][device_id]['process_memory']\
                        [process_id]['MemAllocIncrements']=0

                    # gather mem-stats details
                    if device_id < 100:
                        device='-module {0}'.format(device_id)
                    else:
                        device='-fex {0}'.format(device_id)
                    # TODO: for later enhancement, get output for a list of procs
                    mem_stats_dict=getMemStatsDetailDict(hdl,self.log,proc_name,device)
                    if not mem_stats_dict:
                        # The right thing to do here is probably fail the case
                        #testResult('fail','Did not find memstats info for {0} module {1} for {2}'\
                        #    .format(switch_id,device_id,proc_name),self.log)
                        self.log.info('Did not find memstats info for {0} module {1} for {2}'\
                            .format(switch_id,device_id,proc_name))
                    for struct_id in mem_stats_dict.keys():
                        self.mem_dict[switch_id][device_id]['process_memory']\
                            [process_id][struct_id]={}
                        self.mem_dict[switch_id][device_id]['process_memory']\
                            [process_id][struct_id]['allocs']=[mem_stats_dict[struct_id]['allocs']]
                        self.mem_dict[switch_id][device_id]['process_memory']\
                            [process_id][struct_id]['bytes']=[mem_stats_dict[struct_id]['bytes']]
                        self.mem_dict[switch_id][device_id]['process_memory']\
                            [process_id][struct_id]['allocs_increments']=0

            # Save data to a file
            app_data_dir=os.path.dirname(self.log.handlers[0].baseFilename) + '/' + hdl.switchName + '/memleak/'
            try:
                os.makedirs(app_data_dir)
            except OSError:
                pass
            with open('{0}/seed'.format(app_data_dir),'w') as seed_file:
                seed_file.write('0')
            with open('{0}/memdata-0'.format(app_data_dir),'w') as outputfile:
                outputfile.write(yaml.dump(self.mem_dict))

        return

    # TODO: now check for leaks
    def checkMemLeak(self,*args):
        '''Check for memory leak.

        Usage:
         result=obj.checkMemLeak() # get info for all sup+modules+fex
         result=obj.checkMemLeak('-sup all') # get info for sup only
         result=obj.checkMemLeak('-fex all') # get info for all fex only
         result=obj.checkMemLeak('-fex none') # get info for all sup+modules only
         result=obj.checkMemLeak('-sup active') # get info for active sup only
         result=obj.checkMemLeak('-module 3,4') # get info for these modules only
         result=obj.checkMemLeak('-fex 101,102') # get info for these fex only
         result=obj.checkMemLeak('-process aaa') # get info for this process only
         result=obj.checkMemLeak('-memleak_ignore ['aaa','radius']') # ignore memleak for these'''

        arggrammar={}
        arggrammar['sup']='-type str -choices ["active","standby","all"]'
        arggrammar['module']='-type str -format [0-9,]+'
        arggrammar['fex']='-type str -format [0-9,]+|all|none'
        arggrammar['mutualExclusive'] =[('sup','module','fex')]
        arggrammar['process']='-type str -default all'
        arggrammar['memleak_ignore']='-type list -default []'

        options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log,'namespace')
    
        if not options_namespace.VALIDARGS:
            self.log.warning('Invalid arguments')
            self.result='fail'
            return 
    
        self.memleak_ignore_list.extend(options_namespace.memleak_ignore)

        # TODO: later optimize this to use runParallel to save time
        for switch_id in self.switch_ids:
            hdl=self.switch_ids[switch_id]

            # Option1: If device options need to be specified for checkMemLeak then do as in init
            # Option2(preferred): We can use self.device_list[switch_id] and operate on devices that are online
            # Option3: Check for all online devices in the system and operate on those

            # Option2
            # Get list of online devices in each switch
            online_modules=getModuleList(hdl,self.log)
            online_modules=sorted(map(int,online_modules))
            online_fexs=getFexModuleList(hdl,self.log)
            online_fexs=sorted(map(int,online_fexs))

            # Make a list of online devices that are of interest
            device_list=[]
            for device_id in self.device_list[switch_id]:
                if device_id in online_modules or device_id in online_fexs:
                    device_list.append(device_id)
                else:
                    # Discard old info if a module goes offline
                    self.mem_dict[switch_id].pop(device_id)

            device_list=sorted(map(int,device_list))
            module_ids=','.join(map(str,device_list[:bisect.bisect_left(device_list,100)]))
            fex_ids=','.join(map(str,device_list[bisect.bisect_left(device_list,100):]))
            devices=''
            if module_ids:
                devices+='-module ' + module_ids
            if fex_ids:
                devices+=' -fex ' + fex_ids

            system_resources_dict=getSystemResourcesDict(hdl,self.log,devices)
            process_memory_dict=getProcessesMemoryDict(hdl,self.log,devices)

            for device_id in device_list:

                # Skipping FEXs for now since commands dont work on it
                if device_id >= 100:
                    continue

                # Bit of hard coding here to get device type. Fix this later
                if int(device_id) > 0 and int(device_id) <= 16:
                    device_type='lc'
                elif int(device_id) >= 21 and int(device_id) <= 26:
                    device_type='fc'
                elif int(device_id) >= 27 and int(device_id) <= 28:
                    device_type='sup'
                elif int(device_id) >= 29 and int(device_id) <= 30:
                    device_type='sc'
                elif int(device_id) >= 100:
                    device_type='fex'

                # gather system memory info
                try:
                    used_mem=re.search('([0-9]+)',\
                        system_resources_dict[device_id]['Memory usage']['used']).group(1)
                except:
                    # The right thing to do here is probably fail the case
                    testResult('fail','Did not find system memory info for {0} module {1}'\
                        .format(switch_id,device_id),self.log)
                    used_mem='0'

                diff=int(used_mem) - int(self.mem_dict[switch_id][device_id]['system_memory']['MemUsed'][-1])
                if diff > 0:
                    self.mem_dict[switch_id][device_id]['system_memory']['increments']+=1
                else:
                    # This is to ensure that only contiguous increments are tracked
                    self.mem_dict[switch_id][device_id]['system_memory']['increments']=0

                if diff > (int(self.mem_dict[switch_id][device_id]['system_memory']['MemUsed'][0]) * \
                    self.memleak_threshold_dict[device_type]['system_memory']['percentage'] / 100):
                    self.log.error('System memory has crossed percentage threshold of {0}% for {1} module {2}. Original: {3}  Current: {4}'\
                        .format(self.memleak_threshold_dict[device_type]['system_memory']['percentage'],switch_id,device_id,\
                        self.mem_dict[switch_id][device_id]['system_memory']['MemUsed'][0],used_mem))
                    self.alert=max(self.alert,memUtils.orange)
                    resourceMon.system_memory_result.update({switch_id:{device_id:'fail'}})
                if self.mem_dict[switch_id][device_id]['system_memory']['increments'] > \
                    self.memleak_threshold_dict[device_type]['system_memory']['increments']:
                    self.log.error('System memory has crossed increment threshold of {0} times for {1} module {2}. Original: {3}  Current: {4}'\
                        .format(self.memleak_threshold_dict[device_type]['system_memory']['increments'],switch_id,device_id,\
                        self.mem_dict[switch_id][device_id]['system_memory']['MemUsed'][0],used_mem))
                    self.alert=max(self.alert,memUtils.orange)
                    resourceMon.system_memory_result.update({switch_id:{device_id:'fail'}})

                self.mem_dict[switch_id][device_id]['system_memory']['MemUsed'].append(used_mem)

                if device_id not in process_memory_dict or not process_memory_dict[device_id]:
                    # The right thing to do here is probably fail the case
                    testResult('fail','Did not find process memory info for {0} module {1}'\
                        .format(switch_id,device_id),self.log)
                    process_memory_dict[device_id]={}

                # If a process is not running anymore then discard old data
                process_id_list=self.mem_dict[switch_id][device_id]['process_memory'].keys()
                for pid,proc_name in process_id_list:
                    if pid not in process_memory_dict[device_id].keys() or \
                        proc_name != process_memory_dict[device_id][pid]['Process']:
                        process_id=(pid,proc_name)
                        self.log.info('Process {0} is not running anymore on {1} module {2}'\
                            .format(process_id,switch_id,device_id))
                        self.mem_dict[switch_id][device_id]['process_memory'].pop(process_id)

                # gather process memory info
                for pid in process_memory_dict[device_id].keys():
                    proc_name=process_memory_dict[device_id][pid]['Process']
                    if proc_name not in memUtils.procs_of_interest_list:
                        continue
                    # skip processes of disinterest
                    #if proc_name in memUtils.procs_of_disinterest_list:
                    #    continue
                    # skip processes in ignore list
                    if proc_name in self.memleak_ignore_list:
                        continue
                    # keep process_id unique with this combo
                    process_id=(pid,proc_name)

                    if process_id not in self.mem_dict[switch_id][device_id]['process_memory']:
                        # If this is a new process then add it fresh into db
                        self.log.info('Found new running process {0} on {1} module {2}'\
                            .format(process_id,switch_id,device_id))
                        self.mem_dict[switch_id][device_id]['process_memory'][process_id]={}
                        self.mem_dict[switch_id][device_id]['process_memory']\
                            [process_id]['MemUsed']=[process_memory_dict[device_id][pid]['MemUsed']]
                        self.mem_dict[switch_id][device_id]['process_memory']\
                            [process_id]['MemUsedIncrements']=0
                        self.mem_dict[switch_id][device_id]['process_memory']\
                            [process_id]['MemAlloc']=[process_memory_dict[device_id][pid]['MemAlloc']]
                        self.mem_dict[switch_id][device_id]['process_memory']\
                            [process_id]['MemAllocIncrements']=0

                        # gather mem-stats details
                        if device_id < 100:
                            device='-module {0}'.format(device_id)
                        else:
                            device='-fex {0}'.format(device_id)
                        # TODO: for later enhancement, get output for a list of procs
                        mem_stats_dict=getMemStatsDetailDict(hdl,self.log,proc_name,device)
                        if not mem_stats_dict:
                            # The right thing to do here is probably fail the case
                            #testResult('fail','Did not find memstats info for {0} module {1} for {2}'\
                            #    .format(switch_id,device_id,proc_name),self.log)
                            self.log.info('Did not find memstats info for {0} module {1} for {2}'\
                                .format(switch_id,device_id,proc_name))
                        for struct_id in mem_stats_dict.keys():
                            self.mem_dict[switch_id][device_id]['process_memory']\
                                [process_id][struct_id]={}
                            self.mem_dict[switch_id][device_id]['process_memory']\
                                [process_id][struct_id]['allocs']=[mem_stats_dict[struct_id]['allocs']]
                            self.mem_dict[switch_id][device_id]['process_memory']\
                                [process_id][struct_id]['bytes']=[mem_stats_dict[struct_id]['bytes']]
                            self.mem_dict[switch_id][device_id]['process_memory']\
                                [process_id][struct_id]['allocs_increments']=0

                    else:
                        # This process existed when we checked last time. So compare
                        mem_used=process_memory_dict[device_id][pid]['MemUsed']
                        diff=int(mem_used) - int(self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemUsed'][-1])
                        if diff > 0:
                            self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemUsedIncrements']+=1
                        else:
                            # This is to ensure that only contiguous increments are tracked
                            self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemUsedIncrements']=0

                        if diff > (int(self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemUsed'][0]) * \
                            self.memleak_threshold_dict[device_type]['process_memory']['percentage'] / 100):
                            self.log.error('Process used-memory has crossed percentage threshold of {0}% for {1} on {2} module {3}. Original: {4}  Current: {5}'\
                                .format(self.memleak_threshold_dict[device_type]['process_memory']['percentage'],process_id,switch_id,device_id,\
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemUsed'][0],mem_used))
                            self.alert=max(self.alert,memUtils.orange)
                            resourceMon.process_memory_result.update({switch_id:{device_id:'fail'}})
                        if self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemUsedIncrements'] > \
                            self.memleak_threshold_dict[device_type]['process_memory']['increments']:
                            self.log.error('Process used-memory has crossed increment threshold of {0} times for {1} on {2} module {3}. Original: {4}  Current: {5}'\
                                .format(self.memleak_threshold_dict[device_type]['process_memory']['increments'],process_id,switch_id,device_id,\
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemUsed'][0],mem_used))
                            self.alert=max(self.alert,memUtils.orange)
                            resourceMon.process_memory_result.update({switch_id:{device_id:'fail'}})

                        self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemUsed'].append(mem_used)

                        mem_alloc=process_memory_dict[device_id][pid]['MemAlloc']
                        diff=int(mem_alloc) - int(self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemAlloc'][-1])
                        if diff > 0:
                            self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemAllocIncrements']+=1
                        else:
                            # This is to ensure that only contiguous increments are tracked
                            self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemAllocIncrements']=0

                        if self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemAllocIncrements'] > \
                            self.memleak_threshold_dict[device_type]['process_allocs']['increments']:
                            self.log.error('Process memory-alloc has crossed increment threshold of {0} times for {1} on {2} module {3}. Original: {4}  Current: {5}'\
                                .format(self.memleak_threshold_dict[device_type]['process_allocs']['increments'],process_id,switch_id,device_id,\
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemAlloc'][0],mem_alloc))
                            self.alert=max(self.alert,memUtils.orange)
                            resourceMon.process_memory_result.update({switch_id:{device_id:'fail'}})

                        self.mem_dict[switch_id][device_id]['process_memory'][process_id]['MemAlloc'].append(mem_alloc)

                        # gather mem-stats details
                        if device_id < 100:
                            device='-module {0}'.format(device_id)
                        else:
                            device='-fex {0}'.format(device_id)
                        # TODO: for later enhancement, get output for a list of procs
                        mem_stats_dict=getMemStatsDetailDict(hdl,self.log,proc_name,device)
                        if not mem_stats_dict:
                            # The right thing to do here is probably fail the case
                            #testResult('fail','Did not find memstats info for {0} module {1} for {2}'\
                            #    .format(switch_id,device_id,proc_name),self.log)
                            self.log.info('Did not find memstats info for {0} module {1} for {2}'\
                                .format(switch_id,device_id,proc_name))
                        for struct_id in mem_stats_dict.keys():
                            struct_alloc=mem_stats_dict[struct_id]['allocs']
                            struct_bytes=mem_stats_dict[struct_id]['bytes']
                            if struct_id not in self.mem_dict[switch_id][device_id]['process_memory'][process_id]:
                                # This means a new struct was encountered which wasnt there earlier
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]={}
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['allocs']=[struct_alloc]
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['bytes']=[struct_bytes]
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['allocs_increments']=0
                                continue
                            diff=int(struct_alloc) - int(self.mem_dict[switch_id][device_id]['process_memory'][process_id]\
                                [struct_id]['allocs'][-1])
                            if diff > 0:
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['allocs_increments']+=1
                            else:
                                # This is to ensure that only contiguous increments are tracked
                                self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['allocs_increments']=0

                            if self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['allocs_increments'] > \
                                self.memleak_threshold_dict[device_type]['structure_allocs']['increments']:
                                self.log.error('Process structure-alloc has crossed increment threshold of {0} times for {1} {2} on {3} module {4}. Original: {5}  Current: {6}'\
                                    .format(self.memleak_threshold_dict[device_type]['structure_allocs']['increments'],process_id,struct_id,switch_id,device_id,\
                                    self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['allocs'][0],struct_alloc))
                                self.alert=max(self.alert,memUtils.red)
                                resourceMon.memstats_result.update({switch_id:{device_id:'fail'}})
    
                            self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['allocs'].append(struct_alloc)
                            self.mem_dict[switch_id][device_id]['process_memory'][process_id][struct_id]['bytes'].append(struct_bytes)

            # Save data to a file
            app_data_dir=os.path.dirname(self.log.handlers[0].baseFilename) + '/' + hdl.switchName + '/memleak/'
            with open('{0}/seed'.format(app_data_dir),'r') as seed_file:
                seed=int(seed_file.read())
            with open('{0}/memdata-{1}'.format(app_data_dir,seed+1),'w') as outputfile:
                outputfile.write(yaml.dump(self.mem_dict))
            with open('{0}/seed'.format(app_data_dir),'w') as seed_file:
                seed_file.write(str(seed+1))


class resourceMon(object):
    '''Definitions for resourceMon. 
       To be called ONLY from test cases in module resource_mon running with hlite'''

    # Result Definitions
    # Structure: {switch_id: {module : <pass/fail>}}
    overall_result={}
    system_memory_result={}
    process_memory_result={}
    memstats_result={}
    fd_result={}
    df_result={}
    ls_result={}
    overall_report={}

    def __init__(self,testcasename):

        if testcasename != "generateReport":
            # Initialize the summary results
            resourceMon.overall_result.update(\
                {testcasename : {\
                    'system_memory_result' : {},\
                    'process_memory_result' : {},\
                    'memstats_result' : {},\
                    'fd_result' : {},\
                    'df_result' : {},\
                    'ls_result' : {}\
            }})

            resourceMon.system_memory_result=resourceMon.overall_result[testcasename]['system_memory_result']
            resourceMon.process_memory_result=resourceMon.overall_result[testcasename]['process_memory_result']
            resourceMon.memstats_result=resourceMon.overall_result[testcasename]['memstats_result']
            resourceMon.fd_result=resourceMon.overall_result[testcasename]['fd_result']
            resourceMon.df_result=resourceMon.overall_result[testcasename]['df_result']
            resourceMon.ls_result=resourceMon.overall_result[testcasename]['ls_result']
        else:
            #print ('#######################################################')
            #print resourceMon.overall_result
            #print '#######################################################'

            for testcase in resourceMon.overall_result:
                resourceMon.overall_report[testcase]={}
                for result_type in resourceMon.overall_result[testcase]:
                    for switch_id in resourceMon.overall_result[testcase][result_type]:
                        if switch_id not in resourceMon.overall_report[testcase]:
                            resourceMon.overall_report[testcase][switch_id]={}
                        for module in resourceMon.overall_result[testcase][result_type][switch_id]:
                            if module not in resourceMon.overall_report[testcase][switch_id]:
                                resourceMon.overall_report[testcase][switch_id][module]={}
                            resourceMon.overall_report[testcase][switch_id][module][result_type]=\
                                resourceMon.overall_result[testcase][result_type][switch_id][module]

            #print '#######################################################'
            #print resourceMon.overall_report
            #print '#######################################################'

            for testcase in resourceMon.overall_report:
                for switch_id in resourceMon.overall_report[testcase]:
                    for module in resourceMon.overall_report[testcase][switch_id]:
                        for result_type in resourceMon.overall_result[testcase]:
                            if result_type not in resourceMon.overall_report[testcase][switch_id][module]:
                                resourceMon.overall_report[testcase][switch_id][module][result_type]='--'

            #print '#######################################################'
            #print resourceMon.overall_report
            #print '#######################################################'
                                

    def printReport(self,overall_report):
        message=''
        for testcasename in overall_report:
            report_dict=overall_report[testcasename]
            if not report_dict:
                continue
            switch_id=report_dict.keys()[0]
            module=report_dict[switch_id].keys()[0]
            test_list=report_dict[switch_id][module].keys()
            tests=[]
            for test in test_list:
                if test=='system_memory_result':
                    test='Sys mem | '
                if test=='process_memory_result':
                    test='Proc mem | '
                if test=='memstats_result':
                    test='Memstats | '
                if test=='fd_result':
                    test='FileDesc | '
                if test=='df_result':
                    test='Filesyst | '
                if test=='ls_result':
                    test='Files | '
                tests.append(test)
    
            num_of_tests=len(tests)
            tests.insert(0,'Module | ')
            tests.insert(0,'Switch ID | ')
            tests.insert(0,'Test Name | ')
            columns='%21s %15s %9s'
            for i in range(num_of_tests):
                columns+=' %11s'
    
            #print '======================================================================================================================='
            #message+='=======================================================================================================================\n'
            #print columns % tuple(tests)
            message+= columns % tuple(tests)
            message+='\n'
            #print '-----------------------------------------------------------------------------------------------------------------------'
            message+='-----------------------------------------------------------------------------------------------------------------------\n'
    
            columns='%21s %15s %9s'
            for i in range(num_of_tests):
                columns+=' %11s'
    
            break
    
        for testcasename in overall_report:
            for switch_id in report_dict:
                for module in report_dict[switch_id]:
                    values=[]
                    for test in report_dict[switch_id][module]:
                        value=report_dict[switch_id][module][test]
                        values.append(value+' | ')
    
                    value=module
                    values.insert(0,str(value)+' | ')
    
                    if type(switch_id) is tuple:
                        val1=switch_id[0]
                        val2=switch_id[1]
                        value=val1
                    else:
                        value=switch_id
                    value=(value[:10] + '..') if len(value) > 10 else value
                    values.insert(0,value+' | ')
    
                    value=testcasename
                    value=(value[:16] + '..') if len(value) > 16 else value
                    values.insert(0,value+' | ')
    
                    #print columns % tuple(values)
                    message+= columns % tuple(values)
                    message+='\n'
                    #print '-----------------------------------------------------------------------------------------------------------------------'
                    message+='-----------------------------------------------------------------------------------------------------------------------\n'
            #print '\n'
            #message+='\n\n'

        if message=='':
            #print '  --'
            message+='  --\n'

        return message
    

def getPimNeighborCount(hdl,log,*args):

    #Returns the count of pim neighbors

    msg='Fetch pim neighbor count on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['neighbor']='-type str'
    arggrammer['interface']='-type str'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    priority='[0-9]+'
    bidir='yes|no'
    state='Up|Down|n/a'

    sw_cmd='show ip pim neighbor'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getPimNeighborCount"
         print (msg)
         log.info(msg)
         return 0
    if ns.neighbor and ns.interface:
        msg='Invalid arguments in method:getPimNeighborCount:-neighbor & -interface are exclusive'
        print (msg)
        log.info(msg)
        return 0
    if ns.neighbor:
        sw_cmd+=' '+ns.neighbor
    if ns.interface:
        sw_cmd+=' '+ns.interface    
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    
    pattern='({0}) +({1}) +({2}) +({3}) +({4}) +({5}) +({6})'.format(rex.IP_ADDRESS,rex.INTERFACE_NAME,rex.UPTIME,rex.XPTIME,priority,bidir,state)
    print ("PATTERN: ",pattern)
    neighbor_list=re.findall(pattern,output,re.I)
    print ("neighbor_list:",neighbor_list)
    print ("len(neighbor_list):",len(neighbor_list))
    return len(neighbor_list)

def getFwdL2MrouteCountDict(hdl,log,*args):
    #Returns the dictionary of fwding L2 mroute count info


    msg='Fetch fwding L2 mroute count info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['module']='-type int'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    sw_cmd='show system internal l2mcast info statistics'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getFwdL2MrouteCountDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.module:
        sw_cmd+=' module '+ns.module

    output=hdl.execute(sw_cmd)
    pattern='slot +([0-9]+)\s+=+\s+Entry counts:\-\s+\-+\s+Total HW entries +:([0-9]+)\s+Total OMF entries +:([0-9]+)\s+Total \(\*, G\) entries +:([0-9]+)\s+Total \(S, G\) entries +:([0-9]+)\s+Number of pending entries +:([0-9]+)\s+'
    match=re.findall(pattern,output,re.I|re.DOTALL)
    if len(match):
       return convertListToDict(match,['slot','total_hw_entries','total_omf_entries','total_starg_entries','total_sg_entries','pending_entries'],['slot'])
    else :
       return {}


def getFwdMrouteCountDict(hdl,log,*args):
    #Returns the dictionary of fwding mroute count info


    msg='Fetch fwding mroute count info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    sw_cmd='show forwarding ipv4 multicast route summary'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getFwdMrouteCountDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf

    output=hdl.execute(sw_cmd)
    pattern='slot +([0-9]+)[\r\n\t =]+IPv4 Multicast Routing Table for Context.*?Total number of routes: ([0-9]+).*?Total number of \(\*,G\) routes: ([0-9]+).*?Total number of \(S,G\) routes: ([0-9]+).*?Total number of \(\*,G-prefix\) routes: ([0-9]+).*?Group count: ([0-9]+).*?Prefix insert fail count: ([0-9]+)'
    match=re.findall(pattern,output,re.I|re.DOTALL)
    if len(match):
       return convertListToDict(match,['slot','total_routes','starg_routes','sg_routes','starg_prefix_routes',
                   'group_count','prefix_insert_fail'],['slot'])
    else :
       return {}

def getFwdV6MrouteCountDict(hdl,log,*args):
    #Returns the dictionary of fwding ipv6 mroute count info


    msg='Fetch fwding ipv6 mroute count info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    sw_cmd='show forwarding ipv6 multicast route summary'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getFwdV6MrouteCountDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf

    output=hdl.execute(sw_cmd)
    pattern='slot +([0-9]+)[\r\n\t =]+IPv6 Multicast Routing Table for Context.*?Total number of routes: ([0-9]+).*?Total number of \(\*,G\) routes: ([0-9]+).*?Total number of \(S,G\) routes: ([0-9]+).*?Total number of \(\*,G-prefix\) routes: ([0-9]+).*?Group count: ([0-9]+).*?Prefix insert fail count: ([0-9]+)'
    match=re.findall(pattern,output,re.I|re.DOTALL)
    if len(match):
       return convertListToDict(match,['slot','total_routes','starg_routes','sg_routes','starg_prefix_routes',
                   'group_count','prefix_insert_fail'],['slot'])
    else :
       return {}

def getFwdRouteModuleDict(hdl,log,*args):
    #Returns the dictionary of forwarding route table on a module
 
    arggrammer={}
    arggrammer['module']='-type str -required True'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
   
    msg='Fetch forwarding route table on module {0} on {0}'.format(ns.module, hdl.switchName)
    log.info(msg)

    sw_cmd='show forwarding route module {0}'.format(ns.module)
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)

    route_dict={}
    eol='[ \t\r\n]+'
    sub_pattern='[ \t]*?([a-zA-Z0-9\.]+)[ \t]+({0})'.format(rex.INTERFACE_NAME)
    pattern='({0})\/([0-9]+)[ \t]+((?:{1}{2})+)'.format(rex.IP_ADDRESS,sub_pattern,eol)
    capture_pattern='([a-zA-Z0-9\.]+)[ \t]+({0})'.format(rex.INTERFACE_NAME)
    match=re.findall(pattern,output,re.I|re.DOTALL)
    if len(match):
       for route in match:
           sub_match=re.findall(capture_pattern,route[2],re.I|re.DOTALL)
           next_hop={}
           for nh in sub_match:
               next_hop[nh[0].lower()]={}
               next_hop[nh[0].lower()]['interface']=nh[1].strip().strip(',')
           tmp={}
           tmp[route[0], route[1]]={'nexthop':next_hop}
           route_dict.update(tmp)

    return route_dict 

def getFwdRouteCountDict(hdl,log,*args):
    #Returns the dictionary of fwding unicast route count info


    msg='Fetch fwding unicast route count info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    sw_cmd='show forwarding ipv4 route summary'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getFwdMrouteCountDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    pattern='slot +([0-9]+)[\r\n\t =]+IPv4 routes for table.*?Cumulative route updates: ([0-9]+).*?Cumulative route inserts: ([0-9]+).*?Cumulative route deletes: ([0-9]+).*?Total number of routes: ([0-9]+).*?Total number of paths : ([0-9]+).*?/8 +: ([0-9]+) +/24 +: ([0-9]+) +/32 +: ([0-9]+)'
    match=re.findall(pattern,output,re.I|re.DOTALL)
    if len(match):
        return convertListToDict(match,['slot','route_updates','route_inserts','route_deletes','total_routes',
               'total_paths','prefix8_routes','prefix24_routes','prefix32_routes'],['slot'])
    else:
        return {}

def getFwdV6RouteCountDict(hdl,log,*args):
    #Returns the dictionary of fwding ipv6 unicast route count info


    msg='Fetch fwding ipv6 unicast route count info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={}
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    sw_cmd='show forwarding ipv6 route summary'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getFwdV6MrouteCountDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    pattern='slot +([0-9]+)[\r\n\t =]+IPv6 routes for table.*?Cumulative route updates: ([0-9]+).*?Cumulative route inserts: ([0-9]+).*?Cumulative route deletes: ([0-9]+).*?Total number of routes: ([0-9]+).*?Total number of paths : ([0-9]+).*?/8 +: ([0-9]+) +/10 +: ([0-9]+) +/64 +: ([0-9]+) +/127 *: ([0-9]+)[\r\n\t ]+/128 *: ([0-9]+)'
    match=re.findall(pattern,output,re.I|re.DOTALL)
    if len(match):
        return convertListToDict(match,['slot','route_updates','route_inserts','route_deletes','total_routes',
               'total_paths','prefix8_routes','prefix10_routes','prefix64_routes','prefix127_routes','prefix128_routes',],['slot'])
    else:
        return {}


class treeNode(object):
    '''Utility to build a tree data structure. Provides ability to get ancestors/descendants/heirarchy
    of any given node in the tree.

    Currently the data in each node is a string. It can be enhanced to carry any kind of data

    Each node in the tree can have one parent and have multiple children 
    '''

    def __init__(self,data=None,parent=None):
        self.data=data
        self.parent=parent
        self.children=[]

    def addChild(self,child):
        self.children.append(child)
        child.parent=self

    def buildDescendants(self,**kwargs):
        search_descendants=kwargs.get('descendants',[])
        if self.data:
            search_descendants.append(self.data)
        for child in self.children:
            child.buildDescendants(descendants=search_descendants)
        return search_descendants

    def buildAncestors(self,**kwargs):
        search_ancestors=kwargs.get('ancestors',[])
        if self.data:
            search_ancestors.insert(0,self.data)
        if self.parent:
            self.parent.buildAncestors(ancestors=search_ancestors)
        return search_ancestors

    def searchDescendants(self,pattern,**kwargs):
        search_node=kwargs.get('node',[])
        if self.data and (self.data.strip() == pattern.strip()):
            search_node.append(self)
            return search_node
        for child in self.children:
            child.searchDescendants(pattern,node=search_node)
            if search_node:
                break 
        return search_node

    def search(self,pattern,*args):

        arggrammar={}
        arggrammar['option']='-type str -choices ["search","ancestors","descendants","heirarchy"]\
            -default search'

        options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,None,'namespace')

        if not options_namespace.VALIDARGS:
            print('Invalid arguments')
            return False

        search_option=options_namespace.option

        search_node=[]
        self.searchDescendants(pattern,node=search_node)
        search_heirarchy=[]
        if search_node:
            search_node=search_node[0]
            if search_option=='search':
                return True
            if search_option=='ancestors' or search_option=='heirarchy':
                search_ancestors=[]
                search_node.buildAncestors(ancestors=search_ancestors)
                search_heirarchy.extend(search_ancestors)
            if search_option=='descendants' or search_option=='heirarchy':
                search_descendants=[]
                search_node.buildDescendants(descendants=search_descendants)
                if search_option=='heirarchy':
                    search_descendants=search_descendants[1:]
                search_heirarchy.extend(search_descendants)
        else:
            if search_option=='search':
                return False
        return search_heirarchy


class configTree(object):
    '''Build a tree of running-config commands. Provides ability to get the ancestors / 
    descendants / an entire heirarchy for any given command from that running-config.

    Usage:
        obj = configTree(getRunningConfig(hdl,log)) # Step 1: Build the tree
       ancestor_list = obj.getAncestors('ip address 1.2.3.4/24')

      getAncestors, getDescendants, getHeirarchy - all return a list of config commands in the order
      search - returns boolean True or False

    Example:
      Lets say part of the running-config is as below:

      class-map type queuing class-ip-multicast
        match qos-group 2
        class class-default
          set qos-group 0

      obj.getAncestors('class class-default') returns:
             ['class-map type queuing class-ip-multicast','  class class-default']

      obj.getDescendants('class class-default') returns:
             ['  class class-default','    set qos-group 0']

      obj.getHeirarchy('class class-default') returns:
             ['class-map type queuing class-ip-multicast','  class class-default','    set qos-group 0']

      obj.search('class class-default') returns:
             True

    '''

    def __init__(self,output,root=treeNode()):
        self.root=root
        self.lines=output.splitlines()
        self.total_lines=len(self.lines)
        self.index=0
        curr_indents=''
        self.buildConfigTree(root,curr_indents)

    def buildConfigTree(self,prev_node,curr_indents):
        while self.index < self.total_lines:
            line=self.lines[self.index]
            if not line.strip():
                self.index+=1
                continue
            indents=re.search('^([ ]*).*',line).group(1)
            if len(indents) == len(curr_indents):
                child_node=treeNode(line,prev_node)
                prev_node.addChild(child_node)
                prev_child=child_node
            elif len(indents) > len(curr_indents):
                self.buildConfigTree(prev_child,indents)
            elif len(indents) < len(curr_indents):
                self.index-=1
                return
            self.index+=1
        return

    def search(self,pattern):
        return self.root.search(pattern,'-option search')

    def getAncestors(self,pattern):
        return self.root.search(pattern,'-option ancestors')

    def getDescendants(self,pattern):
        return self.root.search(pattern,'-option descendants')

    def getHeirarchy(self,pattern):
        return self.root.search(pattern,'-option heirarchy')

def getIpArpDetailDict (hdl,log, *args):
    """
    Return arp details for a given (or all) physical interfaces in a dictionary format.
    If an specific physical interface is not passed all entries are captured including
    where interface name is '-'.
    In case of vPC ARP sync feature it can be used to verify ARP sync for vPCs.
    intf can be single Physical interface or list of interfaces
    Sample Usage:
    getIpArpDetailDict(hdl,log)
    getIpArpDetailDict(hdl,log,'-intf po1')
    """

    arggrammar={}
    arggrammar['intf']='-type str'
    arggrammar['vrf']='-type str'
    argparse=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    intfList=[]
    if argparse.intf:
        intfList = strToList(getFullInterfaceName(log,argparse.intf))
    if (argparse.vrf):
        cmd_out = hdl.execute('show ip arp detail vrf {0}'.format(argparse.vrf))
    else:
        cmd_out = hdl.execute ('show ip arp detail')
    arp_list = []
    if (intfList):
        log.debug('Getting Arp details for {0}'.format(intfList))
        for intf in intfList:
            pat = '({0})\s+({1}|\-)\s+({2})\s+({3})\s+({4})\s+([\+\*\#]?)'.\
                format(rex.IPv4_ADDR,rex.UPTIME,rex.MACADDR,rex.INTERFACE_NAME,intf)
            arp_list += re.findall(pat,cmd_out,flags=re.I)
    else:
        log.debug('Getting Arp details for all physical interfaces:')
        pat = '({0})\s+({1}|\-)\s+({2})\s+({3})\s+({3}|\-)\s+([\+\*\#]?)'.\
            format(rex.IPv4_ADDR,rex.UPTIME,rex.MACADDR,rex.INTERFACE_NAME,intf)
        arp_list = re.findall(pat,cmd_out,flags=re.I)
    return convertListToDict(arp_list,['Address','Age','Mac_Address','Interface','Physical_Interface','Flag'],'Address')


####


def getIpv4LpmRouteDict (hdl,log,*args):
    '''
    Returns a dictionary of LPM routes from show ip route by excluding the /32 routes ..

    Sample Usage:
    getIpv4LpmRouteDict(hdl,log)
    getIpv4LpmRouteDict(hdl,log, '-vrf test_vrf')

    Sample Output:

    Top level key is VRF name
    The next level key is Prefix and Prefix length

    Sample Output:
    
    OrderedDict([('vpc_keep_alive', OrderedDict([(('11.10.0.0', '16'), OrderedDict([('prefix', '11.10.0.0'), ('prefix_len', '16'), ('ubest', '1'), ('mbest', '0'), ('next_hop_dict', {('11.10.10.2', 'Eth3/21'): OrderedDict([('via_ip', '11.10.10.2'), ('via_intf', 'Eth3/21'), ('admin_distance', '0'), ('metric', '0'), ('uptime', '11:26:24')])})])), (('11.10.10.2', '32'), OrderedDict([('prefix', '11.10.10.2'), ('prefix_len', '32'), ('ubest', '1'), ('mbest', '0'), ('next_hop_dict', {('11.10.10.2', 'Eth3/21'): OrderedDict([('via_ip', '11.10.10.2'), ('via_intf', 'Eth3/21'), ('admin_distance', '0'), ('metric', '0'), ('uptime', '11:26:24')])})]))]))]))

    '''

    msg='Fetch ip route info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={} 
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    route_dict=collections.OrderedDict()
    sw_cmd='show ip route'

    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getIpv4LpmRouteDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf

    output=hdl.execute(sw_cmd)

    ecmp_pattern='({0})\/({1}),\s+ubest/mbest:\s+({1})\/({1})'.format( rex.IPv4_ADDR, rex.NUM )
    pattern='({0})\/({1}),\s+ubest/mbest:\s+({1})\/({1}),\s+([a-z0-9\_\-]+)'.format( rex.IPv4_ADDR, rex.NUM )
    via_ip_pattern='\*via\s+({0}),\s+({1}),\s+\[({2})\/({2})\],\s+({3}),\s+([0-9a-zA-Z\-\_]+)'.format(rex.IPv4_ADDR, \
             rex.INTERFACE_NAME,rex.NUM, rex.UPTIME)
    via_ip_pattern2='\*via\s+({0}),\s+\[({1})\/({1})\],\s+({2}),\s+([0-9a-zA-Z\-\_]+)'.format(rex.IPv4_ADDR, \
             rex.NUM, rex.UPTIME)

    ip_route_split_pattern='({0})\/({1}),\s+ubest/mbest:'.format( rex.IPv4_ADDR, rex.NUM )


    route_vrf_split=output.split( 'IP Route Table for' )


    for vrf_route in route_vrf_split:

      if re.search( 'VRF', vrf_route, re.I ):

        vrf_match=re.search( 'VRF\s+\"({0})\"'.format(rex.VRF_NAME), vrf_route, re.I )

        vrf_name=vrf_match.group(1)

        route_dict[vrf_name]=collections.OrderedDict()

        route_line_list=vrf_route.split('\r\n')

        prefix='0.0.0.0'
        prefix_len='0'
 
        for route_line in route_line_list:

             if re.search( pattern, route_line, re.I ):
                 match_list=re.findall( pattern, route_line, re.I )
                 for match in match_list:
                     prefix=match[0]
                     prefix_len=match[1]
                     route_dict[vrf_name][(prefix, prefix_len)]=collections.OrderedDict()
                     route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
                     route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
                     route_dict[vrf_name][(prefix, prefix_len)]['ubest']=match[2]
                     route_dict[vrf_name][(prefix, prefix_len)]['mbest']=match[3]
                     route_dict[vrf_name][(prefix, prefix_len)]['attached']=match[4]
                     route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict']={}

             if re.search( ecmp_pattern, route_line, re.I ):
                 match_list=re.findall( ecmp_pattern, route_line, re.I )
                 for match in match_list:
                     prefix=match[0]
                     prefix_len=match[1]
                     route_dict[vrf_name][(prefix, prefix_len)]=collections.OrderedDict()
                     route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
                     route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
                     route_dict[vrf_name][(prefix, prefix_len)]['ubest']=match[2]
                     route_dict[vrf_name][(prefix, prefix_len)]['mbest']=match[3]
                     route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict']={}

             if re.search( via_ip_pattern, route_line, re.I ):
                 match_list=re.findall( via_ip_pattern, route_line, re.I )
                 for match in match_list:
                      via_ip=match[0]
                      via_intf=match[1]
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]=collections.OrderedDict()
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['via_ip']=via_ip
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['via_intf']=via_intf
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['admin_distance']=match[2]
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['metric']=match[3]
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['uptime']=match[4]

             if re.search( via_ip_pattern2, route_line, re.I ):
                 match_list=re.findall( via_ip_pattern2, route_line, re.I )
                 for match in match_list:
                      via_ip=match[0]
                      via_intf='NA'
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]=collections.OrderedDict()
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['via_ip']=via_ip
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['via_intf']=None
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['admin_distance']=match[1]
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['metric']=match[2]
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['uptime']=match[3]


    lpm_route_dict={}
    for vrf_name in route_dict.keys():
        lpm_route_dict[vrf_name]={}
        for prf_len_key in route_dict[vrf_name].keys():
            prf_len=prf_len_key[1]
            if int(prf_len) != 32:
                lpm_route_dict[vrf_name][prf_len_key]=route_dict[vrf_name][prf_len_key]
    log.info('%%% lpm_route_dict %%% {0}'.format(lpm_route_dict ))
    return lpm_route_dict



####



def getIpv6LpmRouteDict (hdl,log,*args):
    '''
    Returns a dictionary of LPM routes from show ipv6 route by excluding the /128 routes ..

    Sample Usage:
    getIpv6LpmRouteDict(hdl,log)
    getIpv6LpmRouteDict(hdl,log, '-vrf test_vrf')

    Sample Output:

    Top level key is VRF name
    The next level key is Prefix and Prefix length

    Sample Output:
    
    OrderedDict([('default', OrderedDict([(('11.10.0.0', '16'), OrderedDict([('prefix', '11.10.0.0'), ('prefix_len', '16'), ('ubest', '1'), ('mbest', '0'), ('next_hop_dict', {('11.10.10.2', 'Eth3/21'): OrderedDict([('via_ip', '11.10.10.2'), ('via_intf', 'Eth3/21'), ('admin_distance', '0'), ('metric', '0'), ('uptime', '11:26:24')])})])), (('11.10.10.2', '32'), OrderedDict([('prefix', '11.10.10.2'), ('prefix_len', '32'), ('ubest', '1'), ('mbest', '0'), ('next_hop_dict', {('11.10.10.2', 'Eth3/21'): OrderedDict([('via_ip', '11.10.10.2'), ('via_intf', 'Eth3/21'), ('admin_distance', '0'), ('metric', '0'), ('uptime', '11:26:24')])})]))]))]))

    '''

    msg='Fetch ip route info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={} 
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    route_dict=collections.OrderedDict()
    sw_cmd='show ipv6 route'

    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getIpv4LpmRouteDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf

    output=hdl.execute(sw_cmd)

    ecmp_pattern='({0})\/({1}),\s+ubest/mbest:\s+({1})\/({1})'.format( rex.IPv6_ADDR, rex.NUM )
    pattern='({0})\/({1}),\s+ubest/mbest:\s+({1})\/({1}),\s+([a-z0-9\_\-]+)'.format( rex.IPv6_ADDR, rex.NUM )
    via_ip_pattern='\*via\s+({0}),\s+({1}),\s+\[({2})\/({2})\],\s+({3}),\s+([0-9a-zA-Z\-\_]+)'.format(rex.IPv6_ADDR, \
             rex.INTERFACE_NAME,rex.NUM, rex.UPTIME)

    ip_route_split_pattern='({0})\/({1}),\s+ubest/mbest:'.format( rex.IPv6_ADDR, rex.NUM )


    route_vrf_split=output.split( 'IPv6 Routing Table for' )


    for vrf_route in route_vrf_split:

      if re.search( 'VRF', vrf_route, re.I ):

        vrf_match=re.search( 'VRF\s+\"({0})\"'.format(rex.VRF_NAME), vrf_route, re.I )

        vrf_name=vrf_match.group(1)

        route_dict[vrf_name]=collections.OrderedDict()

        route_line_list=vrf_route.split('\r\n')

        prefix='0::0'
        prefix_len='0'
 
        for route_line in route_line_list:

             if re.search( pattern, route_line, re.I ):
                 match_list=re.findall( pattern, route_line, re.I )
                 for match in match_list:
                     prefix=match[0]
                     prefix_len=match[1]
                     route_dict[vrf_name][(prefix, prefix_len)]=collections.OrderedDict()
                     route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
                     route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
                     route_dict[vrf_name][(prefix, prefix_len)]['ubest']=match[2]
                     route_dict[vrf_name][(prefix, prefix_len)]['mbest']=match[3]
                     route_dict[vrf_name][(prefix, prefix_len)]['attached']=match[4]
                     route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict']={}

             if re.search( ecmp_pattern, route_line, re.I ):
                 match_list=re.findall( ecmp_pattern, route_line, re.I )
                 for match in match_list:
                     prefix=match[0]
                     prefix_len=match[1]
                     route_dict[vrf_name][(prefix, prefix_len)]=collections.OrderedDict()
                     route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
                     route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
                     route_dict[vrf_name][(prefix, prefix_len)]['ubest']=match[2]
                     route_dict[vrf_name][(prefix, prefix_len)]['mbest']=match[3]
                     route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict']={}

             if re.search( via_ip_pattern, route_line, re.I ):
                 match_list=re.findall( via_ip_pattern, route_line, re.I )
                 for match in match_list:
                      via_ip=match[0]
                      via_intf=match[1]
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]=collections.OrderedDict()
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['via_ip']=via_ip
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['via_intf']=via_intf
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['admin_distance']=match[2]
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['metric']=match[3]
                      route_dict[vrf_name][(prefix, prefix_len)]['next_hop_dict'][(via_ip, via_intf)]['uptime']=match[4]

    lpm_route_dict={}
    for vrf_name in route_dict.keys():
        lpm_route_dict[vrf_name]={}
        for prf_len_key in route_dict[vrf_name].keys():
            prf_len=prf_len_key[1]
            if int(prf_len) != 32:
                lpm_route_dict[vrf_name][prf_len_key]=route_dict[vrf_name][prf_len_key]
    log.info('%%% lpm_route_dict %%% {0}'.format(lpm_route_dict ))
    return lpm_route_dict




#########




def getHostRouteDict (hdl,log,*args):
    '''
    Returns a dictionary of /32 routes from show ip route

    Sample Usage:
    getHostRouteDict(hdl,log)
    getHostRouteDict(hdl,log, '-vrf all')

    Sample Output:

    Top level key is VRF name
    The next level key is Prefix and Prefix length

     {'default': {('1.8.1.3', '32'): {'uptime': '1d04h', 'attached': 'attached', 'metric': '0', 'egress_intf': 'Vlan8', 'admin_distance': '0', 'prefix': '1.8.1.3', 'next_hop': '1.8.1.3', 'prefix_len': '32', 'type': 'local'}, ('1.6.1.2', '32'): {'uptime': '1d04h', 'attached': 'attached', 'metric': '250', 'egress_intf': 'Vlan6', 'admin_distance': '0', 'prefix': '1.6.1.2', 'next_hop': '1.6.1.2', 'prefix_len': '32', 'type': 'am'}, ('120.80.10.255', '32'): {'uptime': '1d04h', 'attached': 'attached', 'metric': '0', 'egress_intf': 'Eth4/15', 'admin_distance': '0', 'prefix': '120.80.10.255', 'next_hop': '120.80.10.255', 'prefix_len': '32', 'type': 'broadcast'} } } 
    '''

    msg='Fetch ip route info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={} 
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    route_dict=collections.OrderedDict()
    sw_cmd='show ip route detail'

    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getRouteDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf

    output=hdl.execute(sw_cmd)

    patt='({0})\/(32),\s+ubest/mbest:\s+[0-9]+\/[0-9]+,\s+([a-z0-9\_\-]+)\r\n\s+\*via\s+({0}),\s+({1}),\s+\[([0-9]+)\/([0-9]+)\],\s+({2}),\s+([0-9a-zA-Z\_\-]+)'.format( rex.IPv4_ADDR, rex.INTERFACE_NAME, rex.UPTIME )

    #patt2='({0})\/(32),\s+ubest/mbest:\s+[0-9]+\/[0-9]+\r\n\s+\*via\s+({1}),\s+\[([0-9]+)\/([0-9]+)\],\s+({2}),\s+([0-9a-zA-Z\_\-]+)'.format( rex.IPv4_ADDR, rex.INTERFACE_NAME, rex.UPTIME )
    patt2='({0})\/(32),\s+ubest/mbest:\s+[0-9]+\/[0-9]+\r\n\s+\*via\s+({0}),\s+\[([0-9]+)\/([0-9]+)\],\s+({2}),\s+([0-9a-zA-Z\_\-]+)'.format( rex.IPv4_ADDR, rex.INTERFACE_NAME, rex.UPTIME )

    patt3='({0})\/(32),\s+ubest/mbest:\s+[0-9]+\/[0-9]+\r\n\s+\*via\s+({0}),\s+({1}),\s+\[([0-9]+)\/([0-9]+)\],\s+({2}),\s+([0-9a-zA-Z\_\-]+)'.format( rex.IPv4_ADDR, rex.INTERFACE_NAME, rex.UPTIME )



    route_vrf_split=output.split( 'IP Route Table for' )


    for vrf_route in route_vrf_split:

      if re.search( 'VRF', vrf_route, re.I ):

        vrf_match=re.search( 'VRF\s+\"({0})\"'.format(rex.VRF_NAME), vrf_route, re.I )


        vrf_name=vrf_match.group(1)

        route_dict[vrf_name]=collections.OrderedDict()

        match_list=re.findall( patt, vrf_route, re.I )

        # Handles regular /32 routes
        for match in match_list:
            prefix=match[0]
            prefix_len=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]=collections.OrderedDict()
            route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
            route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]['attached']=match[2]
            route_dict[vrf_name][(prefix, prefix_len)]['next_hop']=match[3]
            route_dict[vrf_name][(prefix, prefix_len)]['egress_intf']=match[4]
            route_dict[vrf_name][(prefix, prefix_len)]['metric']=match[5]
            route_dict[vrf_name][(prefix, prefix_len)]['admin_distance']=match[6]
            route_dict[vrf_name][(prefix, prefix_len)]['uptime']=match[7]
            route_dict[vrf_name][(prefix, prefix_len)]['type']=match[8]

        # Handles 0.0.0.0 and 255.255.255.0/32 routes which do not have next hop IP
        match_list=re.findall( patt2, vrf_route, re.I )
        for match in match_list:
            prefix=match[0]
            prefix_len=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]={}
            route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
            route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]['attached']=''
            route_dict[vrf_name][(prefix, prefix_len)]['next_hop']=''
            route_dict[vrf_name][(prefix, prefix_len)]['egress_intf']=match[2]
            route_dict[vrf_name][(prefix, prefix_len)]['metric']=match[3]
            route_dict[vrf_name][(prefix, prefix_len)]['admin_distance']=match[4]
            route_dict[vrf_name][(prefix, prefix_len)]['uptime']=match[5]
            route_dict[vrf_name][(prefix, prefix_len)]['type']=match[6]

        # Handles HSRP/VRRP /32 routes which do not have attached tag
        match_list=re.findall( patt3, vrf_route, re.I )
        for match in match_list:
            prefix=match[0]
            prefix_len=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]={}
            route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
            route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]['attached']=''
            route_dict[vrf_name][(prefix, prefix_len)]['next_hop']=match[2]
            route_dict[vrf_name][(prefix, prefix_len)]['egress_intf']=match[3]
            route_dict[vrf_name][(prefix, prefix_len)]['metric']=match[4]
            route_dict[vrf_name][(prefix, prefix_len)]['admin_distance']=match[5]
            route_dict[vrf_name][(prefix, prefix_len)]['uptime']=match[6]
            route_dict[vrf_name][(prefix, prefix_len)]['type']=match[7]
           
        
    print('%%% route_dict %%%', route_dict )
    return route_dict




####




def getIpv6HostRouteDict (hdl,log,*args):
    '''
    Returns a dictionary of /128 routes from show ipv6 route

    Sample Usage:
    getIpv6HostRouteDict(hdl,log)
    getIpv6HostRouteDict(hdl,log, '-vrf all')

    Sample Output:

    Top level key is VRF name
    The next level key is Prefix and Prefix length

     {OrderedDict([('default', OrderedDict([(('2001::10:20:10:1', '128'), OrderedDict([('prefix', '2001::10:20:10:1'), ('prefix_len', '128'), ('attached', 'attached'), ('next_hop', '2001::10:20:10:1'), ('egress_intf', 'Eth3/6'), ('metric', '0'), ('admin_distance', '0'), ('uptime', '01:12:14'), ('type', 'local')])), (('2001::10:20:20:1', '128'), OrderedDict([('prefix', '2001::10:20:20:1'), ('prefix_len', '128'), ('attached', 'attached'), ('next_hop', '2001::10:20:20:1'), ('egress_intf', 'Eth3/7'), ('metric', '0'), ('admin_distance', '0'), ('uptime', '01:12:14'), ('type', 'local')])), (('2001::10:20:30:1', '128'), OrderedDict([('prefix', '2001::10:20:30:1'), ('prefix_len', '128'), ('attached', 'attached'), ('next_hop', '2001::10:20:30:1'), ('egress_intf', 'Eth4/1'), ('metric', '0'), ('admin_distance', '0'), ('uptime', '01:12:40'), ('type', 'local')])), (('2001::20:20:10:1', '128'), OrderedDict([('prefix', '2001::20:20:10:1'), ('prefix_len', '128'), ('attached', 'attached'), ('next_hop', '2001::20:20:10:1'), ('egress_intf', 'Eth3/3'), ('metric', '0'), ('admin_distance', '0'), ('uptime', '01:12:14'), ('type', 'local')])}


    '''

    msg='Fetch ip route info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={} 
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    route_dict=collections.OrderedDict()
    sw_cmd='show ipv6 route'

    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getIpv6HostRouteDict"
         print (msg)
         log.info(msg)
         return {}

    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf

    output=hdl.execute(sw_cmd)

    patt='({0})\/(128),\s+ubest/mbest:\s+[0-9]+\/[0-9]+,\s+([a-z0-9\_\-]+)\r\n\s+\*via\s+({0}),\s+({1}),\s+\[([0-9]+)\/([0-9]+)\],\s+({2}),\s+([0-9a-zA-Z\_\-]+)'.format( rex.IPv6_ADDR, rex.INTERFACE_NAME, rex.UPTIME )

    #patt2='({0})\/(32),\s+ubest/mbest:\s+[0-9]+\/[0-9]+\r\n\s+\*via\s+({1}),\s+\[([0-9]+)\/([0-9]+)\],\s+({2}),\s+([0-9a-zA-Z\_\-]+)'.format( rex.IPv4_ADDR, rex.INTERFACE_NAME, rex.UPTIME )
    patt2='({0})\/(128),\s+ubest/mbest:\s+[0-9]+\/[0-9]+\r\n\s+\*via\s+({0}),\s+\[([0-9]+)\/([0-9]+)\],\s+({2}),\s+([0-9a-zA-Z\_\-]+)'.format( rex.IPv6_ADDR, rex.INTERFACE_NAME, rex.UPTIME )

    patt3='({0})\/(128),\s+ubest/mbest:\s+[0-9]+\/[0-9]+\r\n\s+\*via\s+({0}),\s+({1}),\s+\[([0-9]+)\/([0-9]+)\],\s+({2}),\s+([0-9a-zA-Z\_\-]+)'.format( rex.IPv6_ADDR, rex.INTERFACE_NAME, rex.UPTIME )



    route_vrf_split=output.split( 'IPv6 Routing Table for' )


    for vrf_route in route_vrf_split:

      if re.search( 'VRF', vrf_route, re.I ):

        vrf_match=re.search( 'VRF\s+\"({0})\"'.format(rex.VRF_NAME), vrf_route, re.I )


        vrf_name=vrf_match.group(1)

        route_dict[vrf_name]=collections.OrderedDict()

        match_list=re.findall( patt, vrf_route, re.I )

        # Handles regular /128 routes
        for match in match_list:
            prefix=match[0]
            prefix_len=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]=collections.OrderedDict()
            route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
            route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]['attached']=match[2]
            route_dict[vrf_name][(prefix, prefix_len)]['next_hop']=match[3]
            route_dict[vrf_name][(prefix, prefix_len)]['egress_intf']=match[4]
            route_dict[vrf_name][(prefix, prefix_len)]['metric']=match[5]
            route_dict[vrf_name][(prefix, prefix_len)]['admin_distance']=match[6]
            route_dict[vrf_name][(prefix, prefix_len)]['uptime']=match[7]
            route_dict[vrf_name][(prefix, prefix_len)]['type']=match[8]

        match_list=re.findall( patt2, vrf_route, re.I )
        for match in match_list:
            prefix=match[0]
            prefix_len=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]={}
            route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
            route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]['attached']=''
            route_dict[vrf_name][(prefix, prefix_len)]['next_hop']=''
            route_dict[vrf_name][(prefix, prefix_len)]['egress_intf']=match[2]
            route_dict[vrf_name][(prefix, prefix_len)]['metric']=match[3]
            route_dict[vrf_name][(prefix, prefix_len)]['admin_distance']=match[4]
            route_dict[vrf_name][(prefix, prefix_len)]['uptime']=match[5]
            route_dict[vrf_name][(prefix, prefix_len)]['type']=match[6]

        match_list=re.findall( patt3, vrf_route, re.I )
        for match in match_list:
            prefix=match[0]
            prefix_len=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]={}
            route_dict[vrf_name][(prefix, prefix_len)]['prefix']=match[0]
            route_dict[vrf_name][(prefix, prefix_len)]['prefix_len']=match[1]
            route_dict[vrf_name][(prefix, prefix_len)]['attached']=''
            route_dict[vrf_name][(prefix, prefix_len)]['next_hop']=match[2]
            route_dict[vrf_name][(prefix, prefix_len)]['egress_intf']=match[3]
            route_dict[vrf_name][(prefix, prefix_len)]['metric']=match[4]
            route_dict[vrf_name][(prefix, prefix_len)]['admin_distance']=match[5]
            route_dict[vrf_name][(prefix, prefix_len)]['uptime']=match[6]
            route_dict[vrf_name][(prefix, prefix_len)]['type']=match[7]
           
        
    print('%%% route_dict %%%', route_dict )
    return route_dict


####



def getRouteDict (hdl,log,*args):
    '''
    Returns a dictionary of ip route
    Sample Usage:
    getRouteDict(hdl,log)
    getRouteDict(hdl,log,'-type am')
    getRouteDict(hdl,log,'-route 100.0.0.4')
    Sample output:
    {('3.3.3.3', '32'): {'next_hop': [{'uptime': '3d01h', 'ip': '3.3.3.3', 'metric': '0', 'preference': '0', 'interface': 'Lo0', 'type': 'local'}, {'uptime': '3d01h', 'ip': '3.3.3.3', 'metric': '0', 'preference': '0', 'interface': 'Lo0', 'type': 'direct'}], 'mbest': '0', 'ubest': '2'}}
    '''

    msg='Fetch ip route info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={} 
    arggrammer['type']='-type str' 
    arggrammer['route']='-type str' 
    arggrammer['vrf']='-type str'
    arggrammer['detail']='-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    route_dict={}
    if ns.detail:
        sw_cmd='show ip route detail'
    else:
        sw_cmd='show ip route'

    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getRouteDict"
         print (msg)
         log.info(msg)
         return {}
    if ns.route:
        sw_cmd+=' '+ns.route
    if ns.type:
        sw_cmd+=' '+ns.type
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf

    output=hdl.execute(sw_cmd)

    eol='[ \t\n\r]*'
    #next-hop interface can either exist or not
    sub_pattern='\*?via {0},(?: {1},)? \[[0-9]+/[0-9]+\], {2},(?: [^ \t\r\n]+,?)+'.format(rex.IPv4_ADDR,rex.INTERFACE_NAME,rex.UPTIME)
    pattern='({0})/([0-9]+), ubest/mbest: ([0-9]+)/([0-9]+).*?{1}((?:{2}{1})+)'.format(rex.IPv4_ADDR,eol,sub_pattern)
    capture_pattern='\*?via ({0}),((?: {1},)?) \[([0-9]+)/([0-9]+)\], ({2}?), ([^ \t\r\n,]+)'.format(rex.IPv4_ADDR,rex.INTERFACE_NAME,rex.UPTIME)
    match=re.findall(pattern,output,re.I)
    if len(match):
        for route in match: 
 
           sub_match=re.findall(capture_pattern,route[4],re.I|re.DOTALL)
           next_hop={}
           for nh in sub_match:
               next_hop[nh[0]]={}
               next_hop[nh[0]]['interface']=nh[1].strip().strip(',')
               next_hop[nh[0]]['preference']=nh[2]
               next_hop[nh[0]]['metric']=nh[3]
               next_hop[nh[0]]['uptime']=nh[4]
               next_hop[nh[0]]['type']=nh[5]
               #nh_dict={}
               #nh_dict['ip']=nh[0]
               #nh_dict['interface']=nh[1].strip().strip(',')
               #nh_dict['preference']=nh[2]
               #nh_dict['metric']=nh[3]
               #nh_dict['uptime']=nh[4]
               #nh_dict['type']=nh[5]
               #next_hop.append(nh_dict)
           tmp={}
           tmp[route[0],route[1]]={'ubest':route[2],'mbest':route[3],'next_hop':next_hop}
           route_dict.update(tmp)


    return route_dict

def getInterfaceMacDict (hdl,log):
    ''' Returns interface mac address dict
    '''

    command = "show interface mac-address "
    showOutput = hdl.execute(command)
    pattern='[ \t]*({0})[ \t]+({1})[ \t]+({2})'.format(rex.INTERFACE_NAME, rex.MACADDR, rex.MACADDR)
    macaddrList=re.findall(pattern,showOutput, re.I)
    log.debug("Interface mac address-table dict " + str(macaddrList))
    interface_mac_dict=convertListToDict(macaddrList,['Interface','Mac_Address','Burn_In_Mac_address'],['Interface'])
    return interface_mac_dict

# To get the keys passed our of the mutualExclusiveKeys 
# Example as follows
#
# arggrammar={}
# arggrammar['a']=''
# arggrammar['b']=''
# arggrammar['c']=''
# arggrammar['mutualExclusive']=[('a','b','c')]
# args='-a 1'
# ns1=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
# getmutualExclusiveKeys(ns1,arggrammar['mutualExclusive']) will return [a]
# getmutualExclusiveValues(ns1,arggrammar['mutualExclusive']) will return ['1']

def getmutualExclusiveKeys(ns,mutualExclusiveKeys):
    returnKeys=[]
    for keys in mutualExclusiveKeys:
        for key in keys:
            if  key in ns.KEYS:
                returnKeys.append(key)
    return returnKeys

def getmutualExclusiveValues(ns,mutualExclusiveKeys):
    returnValues=[]
    for keys in mutualExclusiveKeys:
        for key in keys:
            if  key in ns.KEYS:
                returnValues.append(getattr(ns,key))
    return returnValues
                                 
 
# Inverse of strToExpandedList
# 
# Sample usages
# shortenedList([1,2,3,5,10,12,13,14]) returns ['1-3','5','10','12-14']
# shortenedList([1,5,10,12,13,14,2,3]) returns ['1-3','5','10','12-14']
# shortenedList(['Eth1/1','Eth1/2','Eth1/3','Eth1/10','Eth1/12','Eth1/13','Eth1/14']) returns ['Eth1/1-3','Eth1/10','Eth1/12-14']
# shortenedList(['Eth1/1','Eth1/10','Eth1/12','Eth1/13','Eth1/14','Eth1/2','Eth1/3']) returns ['Eth1/1-3','Eth1/10','Eth1/12-14']
# shortenedList(['Vlan1','Vlan2','Vlan100','Vlan3','Vlan4','Vlan101','Vlan200']) returns ['Vlan1-4','Vlan100-101','Vlan'200']

def shortenedList(inputlist):
    returnlist=[]
    templists={}
    for elem in inputlist:
       listfound=False
       isinterface=False
       isvlan=False
       isdigit=('isdigit' not in dir(elem) or ('isdigit' in dir(elem) and elem.isdigit()))
       if not isdigit:
           isinterface=re.match(rex.INTERFACE_NAME,elem)
           if re.match("[Vv]lan[0-9]+$",elem):
               isvlan=True
               isinterface=False
       else:
           if type(elem) is not str:
              elem=str(elem)
       for key in templists.keys():
           if isdigit and templists[key]['type']=='digit':
               if int(elem)-int(templists[key]['prevelem']) == 1:
                   listfound=True
           if isinterface and templists[key]['type']=='interface':
               prevelemlist=templists[key]['prevelem'].split("/")
               elemlist=elem.split("/")
               if prevelemlist[0:len(prevelemlist)-1] == elemlist[0:len(elemlist)-1] and int(elemlist[len(elemlist)-1]) - int(prevelemlist[len(prevelemlist)-1]) == 1:
                   listfound=True
           if isvlan and templists[key]['type']=='vlan':
               prevvlan=re.search("[Vv]lan([0-9]+)$",templists[key]['prevelem']).group(1)
               curvlan=re.search("[Vv]lan([0-9]+)$",elem).group(1)
               if int(curvlan)-int(prevvlan) == 1:
                   listfound=True
           if listfound:                       
              templists[key]['prevelem']=elem         
              templists[key]['valuelist'].append(elem)
              break
       if not listfound:
           returnlistindex=len(templists.keys())
           templists[returnlistindex]={}
           if isdigit:
               templists[returnlistindex]['type']='digit'
           elif isinterface:
               templists[returnlistindex]['type']='interface'
           elif isvlan:
               templists[returnlistindex]['type']='vlan'
           else:
               templists[returnlistindex]['type']='str'
           templists[returnlistindex]['prevelem']=elem         
           templists[returnlistindex]['valuelist']=[]
           templists[returnlistindex]['valuelist'].append(elem)
        
    for key in templists.keys():
        if len(templists[key]['valuelist']) == 1:
            returnlist.append(templists[key]['valuelist'][0])
        else:
            if templists[key]['type']=='digit':
                returnlist.append("{0}-{1}".format(templists[key]['valuelist'][0],templists[key]['valuelist'][len(templists[key]['valuelist'])-1]))
            elif templists[key]['type']=='interface':
                endvalue=templists[key]['valuelist'][len(templists[key]['valuelist'])-1].split("/")
                endvalue=endvalue[len(endvalue)-1]
                returnlist.append("{0}-{1}".format(templists[key]['valuelist'][0],endvalue))
            elif templists[key]['type']=='vlan':
                endvalue=re.search("[Vv]lan([0-9]+)$",templists[key]['prevelem']).group(1)
                returnlist.append("{0}-{1}".format(templists[key]['valuelist'][0],endvalue))
    return returnlist

# To remove a specific key from a dictionary irrespective of the level
# Removecolumns remove only works for the tabular format
# Usage: removeKeys(inputdict,keytoberemoved)

def removeKeys(inputdict,removekeys):

    if type(inputdict) is dict:
        returndict={}
    elif type(inputdict) is collections.OrderedDict:
        returndict=collections.OrderedDict()
    else:
        return inputdict
    
    for key in inputdict.keys():
        if key in removekeys:
            continue
        if type(inputdict[key]) is dict or type(inputdict[key]) is collections.OrderedDict:
            returndict[key]=removeKeys(inputdict[key],removekeys)
        else:
            returndict[key]=inputdict[key]
    return returndict


def powerCycle(log, *args):
    '''Power cycle a given outlet on a given PDU(Power Distribution Unit).

    Returns False if fails, True if succeeds

    Usage:
     status=powerCycle(log,'-ip 172.23.40.209 -outlet 20')
     status=powerCycle(log,'-ip 172.23.40.209 -outlet 20 -state down')
    '''

    arggrammar={}
    arggrammar['ip']='-type str -required True'
    arggrammar['outlet']='-type str -format [0-9,]+ -required True'
    arggrammar['username']='-type str'
    arggrammar['password'] ='-type str'
    arggrammar['state'] ='-type str -choices ["up","down","cycle"] -default cycle'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return False

    ip=options_namespace.ip
    outlet=options_namespace.outlet
    username=options_namespace.username
    password=options_namespace.password
    state=options_namespace.state

    print('Inside powerCycle for {0} outlet {1}'.format(ip,outlet))
    log.info('Inside powerCycle for {0} outlet {1}'.format(ip,outlet))

    pdu_patterns=[                   \
          'Login:',                  \
          'User Name :',             \
          'Password',                \
          '>',                       \
          'Access to the Control Console will be denied', \
          'Connection refused',      \
          'Username:',               \
          pexpect.EOF,               \
          pexpect.TIMEOUT            \
    ]

    outlet_list=re.split('[, ]+',outlet)

    hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
    done=False
    max_connect_retry=5
    connect_retry=0
    while not done:
        i=hdl.expect(pdu_patterns,timeout=30)
        print(hdl.before + str(hdl.after))
        if i==0:
            # Raritan PDU login
            pdu_type='raritan'
            # Default username for raritan is admin
            if not username:
                username='admin'
            time.sleep(1)
            log.info('username used: {0}'.format(username))
            hdl.send('{0}\r'.format(username))
        elif i==1 or i==6:
            # APC PDU login
            if i == 1:
                pdu_type='apc'
            else:
                pdu_type='apc1'
            # Default username for apc is apc
            if not username:
                username='apc'
            time.sleep(1)
            log.info('username used: {0}'.format(username))
            hdl.send('{0}\r'.format(username))
        elif i==2:
            # Password:
            time.sleep(1)
            if pdu_type is 'apc':
                # Default password for apc is apc
                if not password:
                    password='apc'
                # Login in commandline mode using -c
                if not re.search('-c',password):
                    password=password + ' -c'
            elif pdu_type is 'raritan':
                # Default password for raritan is insieme
                if not password:
                    password='insieme'
            log.info('password used: {0}'.format(password))
            hdl.send('{0}\r'.format(password))
            time.sleep(15)
        elif i==3:
            # Logged in
            for outlet in outlet_list:
                if state in ['down','cycle']:
                    # power down the outlet here
                    log.info('Powering down PDU {0} outlet {1}'.format(ip,outlet))
                    print('Powering down PDU {0} outlet {1}'.format(ip,outlet))
                    if pdu_type is 'raritan':
                        hdl.send('set /system1/outlet{0} powerState=2\r'.format(outlet))
                    if pdu_type is 'apc':
                        hdl.send('off {0}\r'.format(outlet))
                    if pdu_type is 'apc1':
                        hdl.send('power outlets {0} off /y\r'.format(outlet))
                    hdl.expect('>')
                    print(hdl.before)
                if state=='cycle':
                    time.sleep(5)
            for outlet in outlet_list:
                if state in ['up','cycle']:
                    # power up the outlet here
                    log.info('Powering up PDU {0} outlet {1}'.format(ip,outlet))
                    print('Powering up PDU {0} outlet {1}'.format(ip,outlet))
                    if pdu_type is 'raritan':
                        hdl.send('set /system1/outlet{0} powerState=1\r'.format(outlet))
                    if pdu_type is 'apc':
                        hdl.send('on {0}\r'.format(outlet))
                    if pdu_type is 'apc1':
                        hdl.send('power outlets {0} on /y\r'.format(outlet))
                    hdl.expect('>')
                    print(hdl.before)
            done=True
            hdl.send('exit\r')
            hdl.terminate(force=True)
            return True
        elif i==4:
            # Access to the Control Console will be denied
            log.error('Access denied to PDU {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Access denied to PDU {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            hdl.terminate(force=True)
            if connect_retry == max_connect_retry:
                return False
            print('Sleeping for 120 seconds...')
            log.info('Sleeping for 120 seconds...')
            time.sleep(120)
            print('Retrying...')
            log.info('Retrying...')
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
        elif i==5:
            # Connection refused
            log.error('Connection refused to PDU {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection refused to PDU {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            hdl.terminate(force=True)
            if connect_retry == max_connect_retry:
                return False
            print('Sleeping for 30 seconds...')
            log.info('Sleeping for 30 seconds...')
            time.sleep(30)
            print('Retrying...')
            log.info('Retrying...')
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
        elif i==7:
            # EOF
            log.error('Connection failed to PDU {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection failed to PDU {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            hdl.terminate(force=True)
            if connect_retry == max_connect_retry:
                return False
            print('Sleeping for 30 seconds...')
            log.info('Sleeping for 30 seconds...')
            time.sleep(30)
            print('Retrying...')
            log.info('Retrying...')
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
        elif i==8:
            # timedout
            log.error('Connection failed to PDU {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection failed to PDU {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            hdl.terminate(force=True)
            if connect_retry == max_connect_retry:
                return False
            print('Sleeping for 30 seconds...')
            log.info('Sleeping for 30 seconds...')
            time.sleep(30)
            print('Retrying...')
            log.info('Retrying...')
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)



def getIpv6RouteDict (hdl,log,*args):
    '''
    Returns a dictionary of ipv6 routes
    Sample Usage:
    getIpv6RouteDict(hdl,log)
    getIpv6RouteDict(hdl,log,'-type direct,ospf -vrf test')
    Sample output:
    length of match is 1
    {('2001::14:1:0:0', '96'): {'next_hop': {'2001::14:1:1:1': {'interface': 'Eth3/24', 'metric': '0', \
    'type': 'direct,', 'preference': '0', 'uptime': '5d21h'}}, 'mbest': '0', 'ubest': '1'}}
    '''

    msg='Fetch ipv6 route info on switch {0}'.format(hdl.switchName)
    log.info(msg)
 
    arggrammer={} 
    arggrammer['type']='-type str' 
    arggrammer['vrf']='-type str'
    arggrammer['route']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')

    ipv6_route_dict={}
    sw_cmd='show ipv6 route'
    if str(ns)=='Namespace()':
         msg="Invalid arguments in method:getRouteDict"
         print (msg)
         log.info(msg)
         return {}
    if ns.route:
        sw_cmd+=' '+ns.route 
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf

    eol='[ \t\n\r]*'
    
    if ns.type:
        type_list=strtolist(ns.type)
        for type in type_list:
            sw2_cmd=sw_cmd+' '+type
            output=hdl.execute(sw2_cmd)
            sub_pattern='\*?via {0},(?: {1},)? \[[0-9]+/[0-9]+\], {2},.*[^ \t\r\n]+'.format(rex.IPv6_ADDR,rex.INTERFACE_NAME,rex.UPTIME)
            pattern='({0})/([0-9]+), ubest/mbest: ([0-9]+)/([0-9]+).*?{1}((?:{2}{1})+)'.format(rex.IPv6_ADDR,eol,sub_pattern)
            capture_pattern='\*?via ({0}),((?: {1},)?) \[([0-9]+)/([0-9]+)\], ({2}?), ([^ \t\r\n]+)'.format(rex.IPv6_ADDR,rex.INTERFACE_NAME,rex.UPTIME)
            match=re.findall(pattern,output,re.I)
            print('match is {0}'.format(match))
            print('length of match is {0}'.format(len(match)))
            if len(match):
                for route in match:
                    #### convert IPv6 prefix to the exploded format
                    for i in range(len(match)):
                        tmp=list(match[i])
                        tmp[0]=ipaddr.IPv6Address(tmp[0]).exploded
                        match[i]=tuple(tmp)

                    sub_match=re.findall(capture_pattern,route[4],re.I|re.DOTALL)
                    next_hop={}
                    for nh in sub_match:
                        ### convert IPv6 nexthop to the exploded format
                        tmp=list(nh)
                        tmp[0]=ipaddr.IPv6Address(tmp[0]).exploded
                        nh=tuple(tmp)
                        next_hop[nh[0]]={}
                        next_hop[nh[0]]['interface']=nh[1].strip().strip(',')
                        next_hop[nh[0]]['preference']=nh[2]
                        next_hop[nh[0]]['metric']=nh[3]
                        next_hop[nh[0]]['uptime']=nh[4]
                        next_hop[nh[0]]['type']=nh[5].strip(',')
        
                    tmp={}
                    tmp[route[0],route[1]]={'ubest':route[2],'mbest':route[3],'next_hop':next_hop}
                    ipv6_route_dict.update(tmp)
        
    else:   
        output=hdl.execute(sw_cmd)
        #next-hop interface can either exist or not
        sub_pattern='\s+\*?via {0},(?: {1},)? \[[0-9]+/[0-9]+\], {2},.*[^ \t\r\n]+'.format(rex.IPv6_ADDR,rex.INTERFACE_NAME,rex.UPTIME)
        pattern='({0})/([0-9]+), ubest/mbest: ([0-9]+)/([0-9]+).*?{1}((?:{2})+)'.format(rex.IPv6_ADDR,eol,sub_pattern)
        #pattern='({0})/([0-9]+), ubest/mbest: ([0-9]+)/([0-9]+).*?{1}((?:{2}{1})+)'.format(rex.IPv6_ADDR,eol,sub_pattern)
        capture_pattern='\*?via ({0}),((?: {1},)?) \[([0-9]+)/([0-9]+)\], ({2}?), ([^ \t\r\n]+)'.format(rex.IPv6_ADDR,rex.INTERFACE_NAME,rex.UPTIME)
        match=re.findall(pattern,output,re.I)
        if len(match):
            ### convert IPv6 prefix to the exploded format
            for i in range(len(match)):
                tmp=list(match[i])
                tmp[0]=ipaddr.IPv6Address(tmp[0]).exploded
                match[i]=tuple(tmp)
            for route in match:
               sub_match=re.findall(capture_pattern,route[4],re.I|re.DOTALL)
               next_hop={}
               for nh in sub_match:
                   ### convert next-hop to IPv6 exploded format
                   tmp=list(nh)
                   tmp[0]=ipaddr.IPv6Address(tmp[0]).exploded
                   nh=tuple(tmp)
                   next_hop[nh[0]]={}
                   next_hop[nh[0]]['interface']=nh[1].strip().strip(',')
                   next_hop[nh[0]]['preference']=nh[2]
                   next_hop[nh[0]]['metric']=nh[3]
                   next_hop[nh[0]]['uptime']=nh[4]
                   next_hop[nh[0]]['type']=nh[5].strip(',')
    
               tmp={}
               tmp[route[0],route[1]]={'ubest':route[2],'mbest':route[3],'next_hop':next_hop}
               ipv6_route_dict.update(tmp)


    return ipv6_route_dict



#=============================================================================================#
# Function to convert IPV4 address to integer
#=============================================================================================#

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

#=============================================================================================#
# Function to convert Integer to IPV4 address
#=============================================================================================#

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))



#=============================================================================================#
# Function to convert IPV6 address to integer
#=============================================================================================#

def ipv62int(addr):
    return int(ipaddr.IPv6Address(addr))

#=============================================================================================#
# Function to convert Integer to IPV6 address
#=============================================================================================#

def int2ipv6(addr):
    return ipaddr.IPv6Address(addr)


#=============================================================================================#
# Function to increment IPV4 address
#=============================================================================================#

def incrementIpv4Address( addr, addr_step ):
     return int2ip( ip2int(addr) + ip2int(addr_step) )


#=============================================================================================#
# Function to increment IPV6 address
#=============================================================================================#

def incrementIpv6Address( addr, addr_step ):
     return int2ipv6( ipv62int(addr) + ipv62int(addr_step) )


#=============================================================================================#
# Function to expand abbreviated IPV6 address
#=============================================================================================#

def expandIpv6Address( address ):
    fullAddress = "" # All groups
    expandedAddress = "" # Each group padded with leading zeroes
    validGroupCount = 8
    validGroupSize = 4
    if "::" not in address: # All groups are already present
        fullAddress = address
    else: # Consecutive groups of zeroes have been collapsed with "::"
        sides = address.split("::")
        groupsPresent = 0
        for side in sides:
            if len(side) > 0:
                groupsPresent += len(side.split(":"))
        if len(sides[0]) > 0:
            fullAddress += sides[0] + ":"
        for i in range(0,validGroupCount-groupsPresent):
            fullAddress += "0000:"
        if len(sides[1]) > 0:
            fullAddress += sides[1]
        if fullAddress[-1] == ":":
            fullAddress = fullAddress[:-1]
    groups = fullAddress.split(":")
    for group in groups:
        while(len(group) < validGroupSize):
            group = "0" + group
        expandedAddress += group + ":"
    if expandedAddress[-1] == ":":
        expandedAddress = expandedAddress[:-1]
    return expandedAddress

#=============================================================================================#
# Function to increment MAC address
#=============================================================================================#

def incrementMacAddress( addr, addr_step ):
     mac_addr=netaddr.EUI(addr)
     mac_addr_step=netaddr.EUI(addr_step)
     new_mac_addr= netaddr.EUI( int(mac_addr) + int(mac_addr_step))
     return sanitizeMac(new_mac_addr)


#=============================================================================================#
# Function to convert IPV4 address to Binary format
#=============================================================================================#

def ipv4ToBinary( addr ):
     bin_format='.'.join([bin(int(x)+256)[3:] for x in addr.split('.')])
     return bin_format.replace( '.', '')


#=============================================================================================#
# Function to derive the multicast MAC address based on the IPv4 Address
#=============================================================================================#

def ipv4MulticastToMacAddress( addr ):
     bin_addr=ipv4ToBinary( addr )
     # Take the last 23 bits of the binary address
     twenty_three_bits=bin_addr[9:32]
     # Binary for 01-00-5e
     mcast_mac_prf='0000000100000000010111100'
     mcast_mac_bin= mcast_mac_prf + twenty_three_bits
     mac_hex_t=hex(int(mcast_mac_bin, 2 ))
     match=re.search( '0x([0-9,a-f,A-F]+)', mac_hex_t, re.I )
     mac_hex=match.group(1)
     return eui(mac_hex)


#=============================================================================================#
# sanitizeMac - Convert any form of MAC address to 00:00:00:00:00:00 format. Scapy accepts
# MAC address only in this format
#=============================================================================================#

def sanitizeMac(mac):
     if not re.search( 'INCOMPLETE', str(mac), re.I ):
         mac = str(mac).replace( "(", "" ).replace( ")", "").replace("EUI", "")
         temp = str(mac).replace(":", "").replace("-", "").replace(".", "").upper()
         return temp[:2] + ":" + ":".join([temp[i] + temp[i+1] for i in range(2,12,2)])



##################################################################################################

def getShowVdcDict(hdl,log):
    """Method to get VDC details in dict format in NxOS"""

    cmd_out= hdl.execute ('show vdc')
    pat = '({0})\s+({1})\s+([A-Za-z]+)\s+({2})\s+([A-Za-z]+)\s+([A-Z 0-9]+)'.\
        format(rex.NUM,rex.SWITCH_NAME,rex.MACADDR)
    vdc_list=re.findall(pat,cmd_out)
    return convertListToDict(vdc_list,['vdc_id','vdc_name','state','mac','type','lc'],['vdc_name'])

def createVdc(hdl,log,*args):
    """Method to create a VDC in NxOS"""

    if hdl.device_type != 'N7K':
        return False
    arggrammer={} 
    arggrammer['password']='-type str -default insieme' 
    arggrammer['vdc_name']='-type str -required True'
    arggrammer['module_type']='-type str'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammer,log)
    vdc_name = parse_output.vdc_name
    password = parse_output.password
    hdl.hdl.sendline('config terminal')
    hdl.hdl.expect('# $')
    print (hdl.hdl.before)
    hdl.hdl.sendline ('vdc {0}'.format(vdc_name))
    hdl.hdl.expect('# $',timeout=300)
    if parse_output.module_type:
        hdl.hdl.sendline('limit-resource module-type {0}'.format(parse_output.module_type))
        hdl.hdl.expect('\[yes\]')
        print (hdl.hdl.before)
        hdl.hdl.sendline('yes')
        hdl.hdl.expect('# $')
    print (hdl.hdl.before)
    vdc_dict = getShowVdcDict(hdl,log)
    if vdc_name in vdc_dict.keys() and vdc_dict[vdc_name]['state'] == 'active':
        log.debug ('vdc Create successful on {0}'.format(hdl.switchName))
        return True
    else:
        return False

def deleteVdc(hdl,log,*args):

    """Method to delete a VDC in NxOS"""

    if hdl.device_type != 'N7K':
        return False

    arggrammer={} 
    arggrammer['vdc_name']='-type str -required True'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammer,log)
    vdc_name = parse_output.vdc_name
    vdc_dict = getShowVdcDict(hdl,log)
    if vdc_name not in vdc_dict.keys():
        log.debug ('No such vdc exist on {0}'.format(hdl.switchName))
        return False
    hdl.hdl.sendline('config terminal')
    hdl.hdl.expect('# $')
    print (hdl.hdl.before)
    hdl.hdl.sendline ('no vdc {0}'.format(vdc_name))
    exp_prompts = ['Deleting this vdc will remove its config. Continue deleting this vdc \(y/n\)\?  \[no\]',\
                       '# $']
    i=hdl.hdl.expect(exp_prompts,timeout=30)
    print (hdl.hdl.before)
    if i == 0:
        hdl.hdl.sendline ('yes')
    else:
        hdl.hdl.sendline ('\r')
    hdl.hdl.expect('# $',timeout=300)
    print (hdl.hdl.before)
    vdc_dict = getShowVdcDict(hdl,log)
    if vdc_name not in vdc_dict.keys():
        log.debug ('vdc Delete successful on {0}'.format(hdl.switchName))
        return True
    else:
        return False
    
def allocateInterfaceToVdc(hdl,log,interfaces,vdc_name='default'):
    """Method to move interfaces to a VDC in NxOS"""

    if hdl.device_type != 'N7K':
        return False

    if vdc_name == 'default':
        vdc_name = hdl.switchName
    vdc_dict = getShowVdcDict(hdl,log)
    if vdc_name not in vdc_dict.keys():
        log.debug ('No such vdc exist on {0}'.format(hdl.switchName))
        return False
    hdl.hdl.sendline('config terminal')
    hdl.hdl.expect('# $')
    hdl.hdl.sendline('vdc {0}'.format(vdc_name))
    hdl.hdl.expect('# $')
    print (hdl.hdl.before)
    #remove any FEX interface
    interfaces_list = interfaces.split(',')
    for interface in list(interfaces_list):
        if re.search(rex.FEX_INTERFACE_TYPE,interface):
            interfaces_list.remove(interface)
    interfaces =','.join(interfaces_list)
    hdl.hdl.sendline ('allocate interface {0}'.format(interfaces))
    # We are not doing any additional check - can be extended once it's EoR feature
    exp_prompts = ['Are you sure you want to move the ports \(y/n\)\?  \[yes\]',\
                       '# $']
    i=hdl.hdl.expect(exp_prompts,timeout=30)
    print (hdl.hdl.before)
    if i == 0:
        hdl.hdl.sendline ('yes')
    else:
        log.debug('Unexpected response')
        return False
    hdl.hdl.expect('# $',timeout=300)
    print (hdl.hdl.before)
    return True
#############################################################################    


def getInterfaceList(hdl,log,*args):
    """Method to get list of all interfaces of certain type in NXOS
    Default is to return one list having all types of interfaces

    Usage:
       intf_list=getInterfaceList(hdl,log)
       intf_list=getInterfaceList(hdl,log,'-physical') # physical ports only
       intf_list=getInterfaceList(hdl,log,'-vlan') # SVI only
       intf_list=getInterfaceList(hdl,log,'-port_channel -vlan -loopback') # Po, SVI, and lpbk
       intf_list=getInterfaceList(hdl,log,'-physical -status up') 
    """

    arggrammer={} 
    arggrammer['physical']='-type bool'
    arggrammer['vlan']='-type bool'
    arggrammer['port_channel']='-type bool'
    arggrammer['loopback']='-type bool'
    arggrammer['mgmt']='-type bool'
    arggrammer['status']='-type str -default none'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammer,log)

    all=True

    physical = parse_output.physical
    vlan = parse_output.vlan
    po = parse_output.port_channel
    lo = parse_output.loopback
    mgmt = parse_output.mgmt
    status = parse_output.status

    if physical or vlan or po or lo or mgmt:
        all=False

    interface_list=[]
    cmd_out = hdl.execute ('show interface brief')
    if all:
        pat = '^({0})'.format(rex.INTERFACE_NAME)
        interface_list.extend(re.findall(pat,cmd_out,re.M))

    if physical:
        if status == 'none':
            pat = '^({0})'.format(rex.PHYSICAL_INTERFACE_NAME)
        else:
            pat = '^({0})\s+{1}\s+{2}\s+{2}\s+{3}'.format(rex.PHYSICAL_INTERFACE_NAME,rex.ALPHANUMSPECIAL\
                                                               ,rex.ALPHA,status)
        interface_list.extend(re.findall(pat,cmd_out,re.M))

    if vlan:
        pat = '^(Vlan[0-9]+)'
        interface_list.extend(re.findall(pat,cmd_out,re.M))

    if po:
        pat = '^(Po[0-9]+)'
        interface_list.extend(re.findall(pat,cmd_out,re.M))

    if lo:
        pat = '^(Lo[0-9]+)'
        interface_list.extend(re.findall(pat,cmd_out,re.M))

    if mgmt:
        pat = '^(mgmt[0-9]+)'
        interface_list.extend(re.findall(pat,cmd_out,re.M))

    return interface_list
    
###########################################################################

def getClassMapDict(hdl,log,*args):
    """Method to return the dictionary of classmaps for type qos,network-qos,queuing and control-plane with specific name of the class or returns all the classmaps of the given type. If no type or name is given then it will return all the configured class-maps"""

    arggrammar={}
    arggrammar['name']='-type str'
    arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -default qos'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if ns.type:
        if re.search( 'network-qos', ns.type, re.I ):
            if ns.name:
                cmd='show class-map type network-qos {0}'.format(ns.name)
            else:
                cmd='show class-map type network-qos'
        elif re.search( 'qos', ns.type, re.I ):
            if ns.name:
                cmd='show class-map type qos {0}'.format(ns.name)
            else:
                cmd='show class-map type qos'
        elif re.search( 'queuing', ns.type, re.I ):
            if ns.name:
                cmd='show class-map type queuing {0}'.format(ns.name)
            else:
                cmd='show class-map type queuing'
        elif re.search( 'control-plane', ns.type, re.I ):
            if ns.name:
                cmd='show class-map type control-plane {0}'.format(ns.name)
            else:
                cmd='show class-map type control-plane'
    elif ns.name:
        cmd='show class-map {0}'.format(ns.name)
    else:
        cmd='show class-map type qos'

    cmap_dict={}
    show_out=hdl.execute(cmd)
    for line in show_out.split('\n'):
        cmap_type=re.search('class-map type ([^ \t]+)(?: match-(?:all|any))? ([^ \t\r]+)',line)
        match_acl=re.search('match (access-group) name ([^ \t\r]+)',line)
        match_rtp=re.search('match ip (rtp) ([^ \t\r]+)',line)
        match_pkt_len=re.search('match (packet) (length) ([^ \t\r]+)',line)
        if cmap_type:
            ctype=cmap_type.group(1)
            cmap=cmap_type.group(2)
            cmap_dict[(ctype,cmap)]={}
        elif match_acl:
            mtype=match_acl.group(1)
            value=match_acl.group(2)
            cmap_dict[(ctype,cmap)].update({mtype : value})
        elif match_rtp:
            mtype=match_rtp.group(1)
            value=match_rtp.group(2)
            cmap_dict[(ctype,cmap)].update({mtype : value})
        elif match_pkt_len:
            mtype=match_pkt_len.group(1)+match_pkt_len.group(2)
            value=match_pkt_len.group(3)
            cmap_dict[(ctype,cmap)].update({mtype : value})
        else:
            match_type=re.search('match ([^ \t]+) ([^ \t\r]+)',line)
            if match_type:
                mtype=match_type.group(1)
                value=match_type.group(2)
                cmap_dict[(ctype,cmap)].update({mtype : value})
            else:
                match_any=re.search('match ([^ \t\r]+)',line)
                if match_any:
                    mtype=match_any.group(1)
                    cmap_dict[(ctype,cmap)].update({mtype : 'any'})

    return cmap_dict        
def getPolicyMapDict(hdl,log,*args):
    """Method to return the dictionary of policymaps for type qos,network-qos,queuing and control-plane with specific name of the policy or the policies configured under interface/system/vlan or returns all the policy-maps of the given type. If no type or name is given then it will return all the configured policy-maps"""

    arggrammar={}
    arggrammar['name']='-type str'
    arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"]'
    arggrammar['system']='-type bool -default False'
    arggrammar['interface']='-type str -format {0}|control-plane|all'.format(rex.INTERFACE_NAME)
    arggrammar['vlan'] = '-type str'.format(rex.NUM)
    arggrammar['input'] = '-type bool -default False'
    arggrammar['output'] = '-type bool -default False'
    arggrammar['clas'] = '-type str'
    arggrammar['module'] = '-type int'
    arggrammar['brief'] = '-type bool -default False'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if ns.interface:
        if re.search( 'eth|po', ns.interface, re.I ):
            if ns.input:
                if re.search ( 'qos', ns.type, re.I ):
                    cmd='show policy-map interface {0} input type {1}'.format(ns.interface,ns.type)
                elif re.search ( 'queuing', ns.type, re.I ):
                    cmd='show policy-map interface {0} input type {1}'.format(ns.interface,ns.type)
                else:
                    cmd='show policy-map interface {0} input'.format(ns.interface)
            elif ns.output:
                if re.search ( 'qos', ns.type, re.I ):
                    cmd='show policy-map interface {0} output type {1}'.format(ns.interface,ns.type)
                elif re.search ( 'queuing', ns.type, re.I ):
                    cmd='show policy-map interface {0} output type {1}'.format(ns.interface,ns.type)
                else:
                    cmd='show policy-map interface {0} output'.format(ns.interface)
            elif ns.type:
               if re.search ( 'qos', ns.type, re.I ):
                    cmd='show policy-map interface {0} type {1}'.format(ns.interface,ns.type)
               elif re.search ( 'queuing', ns.type, re.I ):
                    cmd='show policy-map interface {0} type {1}'.format(ns.interface,ns.type)
            else:
                cmd='show policy-map interface {0}'.format(ns.interface)
        elif re.search( 'control', ns.interface, re.I ):
            if ns.clas:
                if ns.module:
                    cmd='show policy-map interface {0} class {1} module {2}'.format(ns.interface,ns.clas,ns.module)
                else:
                    cmd='show policy-map interface {0} class {1}'.format(ns.interface,ns.clas)
            if ns.module:
                if ns.clas:
                    cmd='show policy-map interface {0} module {1} class {2}'.format(ns.interface,ns.module,ns.clas)
                else:
                    cmd='show policy-map interface {0} module {1}'.format(ns.interface,ns.module)
            else:
                cmd='show policy-map interface {0}'.format(ns.interface)
        elif ns.input:
            if re.search ( 'qos', ns.type, re.I ):
                cmd='show policy-map interface {0} input type {1}'.format(ns.interface,ns.type)
            elif re.search ( 'queuing', ns.type, re.I ):
                cmd='show policy-map interface {0} input type {1}'.format(ns.interface,ns.type)
            else:
                cmd='show policy-map interface {0} input'.format(ns.interface)
        elif ns.output:
            if re.search ( 'qos', ns.type, re.I ):
                cmd='show policy-map interface {0} output type {1}'.format(ns.interface,ns.type)
            elif re.search ( 'queuing', ns.type, re.I ):
                cmd='show policy-map interface {0} output type {1}'.format(ns.interface,ns.type)
            else:
                cmd='show policy-map interface {0} output'.format(ns.interface)
        elif ns.type:
            if re.search ( 'qos', ns.type, re.I ):
                cmd='show policy-map interface {0} input type {1}'.format(ns.interface,ns.type)
            elif re.search ( 'queuing', ns.type, re.I ):
                cmd='show policy-map interface {0} input type {1}'.format(ns.interface,ns.type)
        elif ns.brief:
            cmd='show policy-map interface {0} brief'.format(ns.interface)
        elif re.search ( 'all', ns.interface, re.I ):
            cmd='show policy-map interface'
    elif ns.system:
        if ns.type:
            if re.search ( 'qos', ns.type, re.I ):
                cmd='show policy-map system type {0}'.format(ns.type)
            elif re.search ( 'network-qos', ns.type, re.I ):
                cmd='show policy-map system type {0}'.format(ns.type)
            elif re.search ( 'queuing', ns.type, re.I ):
                cmd='show policy-map system type {0}'.format(ns.type)
        else:
            cmd='show policy-map system'
    elif ns.vlan:
        if re.search ('[0-9]+', ns.vlan, re.I):
            if ns.input:
                if ns.type:
                    cmd='show policy-map vlan {0} input type qos'.format(ns.vlan)
                else:
                   cmd='show policy-map vlan {0} input'.format(ns.vlan)
            elif ns.output:
                if ns.type:
                    cmd='show policy-map vlan {0} output type qos'.format(ns.vlan)
                else:
                    cmd='show policy-map vlan {0} output'.format(ns.vlan)
            elif ns.type:
                cmd='show policy-map vlan {0} input type qos'.format(ns.vlan)
            else:
                cmd='show policy-map vlan {0}'.format(ns.vlan)

        elif ns.type:
            cmd='show policy-map vlan type qos'
        elif ns.input:
            if ns.type:
                cmd='show policy-map vlan input type qos'
            else:
                cmd='show policy-map vlan input'
        elif ns.output:
            if ns.type:
                cmd='show policy-map vlan output type qos'
            else:
                cmd='show policy-map vlan output'
        elif re.search('all', ns.vlan, re.I):
           cmd='show policy-map vlan'
    elif ns.type:
        if not ns.interface:
            if re.search ('qos', ns.type, re.I):
                if ns.name:
                    cmd='show policy-map type {0} {1}'.format(ns.type,ns.name)
                else:
                    cmd='show policy-map type {0}'.format(ns.type)
            if re.search ('network-qos', ns.type, re.I):
                if ns.name:
                    cmd='show policy-map type {0} {1}'.format(ns.type,ns.name)
                else:
                    cmd='show policy-map type {0}'.format(ns.type)
            if re.search ('queuing', ns.type, re.I):
                if ns.name:
                    cmd='show policy-map type {0} {1}'.format(ns.type,ns.name)
                else:
                    cmd='show policy-map type {0}'.format(ns.type)
            if re.search ('control-plane', ns.type, re.I):
                if ns.name:
                    cmd='show policy-map type {0} name {1}'.format(ns.type,ns.name)
                else:
                    cmd='show policy-map type {0}'.format(ns.type)

    elif ns.name:
        if not ns.interface:
            cmd='show policy-map {0}'.format(ns.name)
    else:
         cmd='show policy-map'

    pmap_dict={}
    show_out=hdl.execute(cmd)
    for line in show_out.split('\n'):
        pmap_if_type=re.search("Service-policy \(([^ \t]+)\) input:\s+([^ \t\r]+)",line)
        if pmap_if_type:
            ptype=pmap_if_type.group(1)
            pmap=pmap_if_type.group(2)
            pmap_dict[(ptype,pmap)]={}
        pmap_copp_type=re.search("[Ss]ervice-policy  input:\s+([^\t\r]+)",line)  # CoPP
        if pmap_copp_type:
            ptype='control-plane'
            pmap=pmap_copp_type.group(1)
            pmap_dict[(ptype,pmap)]={}
        pmap_op_type=re.search("Service-policy \(([^ \t]+)\) output:\s+([^ \t\r]+)",line)
        if pmap_op_type:
            ptype=pmap_op_type.group(1)
            pmap=pmap_op_type.group(2)
            pmap_dict[(ptype,pmap)]={}
        pmap_type=re.search('policy-map type ([^ \t]+) ([^ \t\r]+)',line)
        if pmap_type:
            ptype=pmap_type.group(1)
            pmap=pmap_type.group(2)
            pmap_dict[(ptype,pmap)]={}
        class_if_map=re.search('Class-map \(([^ \t]+)\):\s+([^ \t]+)',line)
        if class_if_map:
            ctype=class_if_map.group(1)
            cmap=class_if_map.group(2)
            pmap_dict[(ptype,pmap)].update({(ctype,cmap):{}})
        class_copp_map=re.search('class-map ([^ \t\r]+)',line)
        if class_copp_map:
            ctype='control-plane'
            cmap=class_copp_map.group(1)
            pmap_dict[(ptype,pmap)].update({(ctype,cmap):{}})
        class_n7k_type=re.search('class\s+([^ \t\r]+)',line)
        if class_n7k_type:
            ctype=ptype
            cmap=class_n7k_type.group(1)
            pmap_dict[(ptype,pmap)].update({(ctype,cmap):{}})
        class_type=re.search('class type ([^ \t]+) ([^ \t\r]+)',line)
        if class_type:
            ctype=class_type.group(1)
            cmap=class_type.group(2)
            pmap_dict[(ptype,pmap)].update({(ctype,cmap):{}})
        copp_class=re.search('class (copp[^ \t\r]+)',line)
        if copp_class:
            ctype='copp'
            cmap=copp_class.group(1)
            pmap_dict[(ptype,pmap)].update({(ctype,cmap):{}})
        set_value=re.search('set ([^ \t]+) ([^ \t\r]+)',line)
        if set_value:
            qos_group=set_value.group(1)
            value=set_value.group(2)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({qos_group : value})
        module_num=re.search('module (\d+)',line)
        if module_num:
            module=module_num.group(1)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({module:{}})
        transmit_pkts=re.search('transmitted (\d+) packets',line)
        if transmit_pkts:
            num=transmit_pkts.group(1)
            pmap_dict[(ptype,pmap)][(ctype,cmap)][module].update({'transmitted packets':num})
        drop_pkts=re.search('dropped (\d+) packets',line)
        if drop_pkts:
            num=drop_pkts.group(1)
            pmap_dict[(ptype,pmap)][(ctype,cmap)][module].update({'dropped packets':num})
        #agg_fwd=re.search('Aggregate forwarded',line)
        agg_fwd_pkt=re.search('([^ \t]+) packets',line)
        #if agg_fwd:
        #    print ('Entered here1 ####')
        if agg_fwd_pkt:
            print ('Entered here2 ####')
            agg_fwd_pkts='agg_fwd_pkts'
            value=agg_fwd_pkt.group(1)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({agg_fwd_pkts : value})
        bw_value=re.search('(bandwidth) remaining percent ([^ \t\r]+)',line)
        if bw_value:
            bw=bw_value.group(1)
            value=bw_value.group(2)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({bw : value}) 
        pri=re.search('(priority)',line)
        if pri:
            priority=pri.group(1)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({priority : 'yes'})
        mtu_value=re.search('(mtu) ([^ \t\r]+)',line)
        if mtu_value:
            mtu=mtu_value.group(1)
            value=mtu_value.group(2)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({mtu : value})
        action_value=re.search('(pause|random-detect|shape|queue-limit) ([^\t\r]+)',line)
        if action_value:
            action=action_value.group(1)
            value=action_value.group(2)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({action : value})
        mcast_value=re.search('(multicast-[^ \t\r]+)',line)
        if mcast_value:
            mcast=mcast_value.group(1)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({mcast : 'yes'})
        cong_control=re.search('(congestion-control) ([^ \t\r]+)',line)
        if cong_control:
            congest=cong_control.group(1)
            value=cong_control.group(2)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({congest : value})
        copp_setcfg=re.search('set (cos) ([^ \t\r]+)',line)
        if copp_setcfg:
            set_cos=copp_setcfg.group(1)
            value=copp_setcfg.group(2)
            pmap_dict[(ptype,pmap)][(ctype,cmap)].update({set_cos : value})
        copp_police=re.search('police (cir) ([0-9]+ [a-zA-Z]+) (bc) ([0-9]+ [a-zA-Z]+) (conform) ([a-zA-Z]+) (violate) ([a-zA-Z]+)',line)
        if copp_police:
            cir=copp_police.group(1)
            cir_value=copp_police.group(2)
            bc=copp_police.group(3)
            bc_value=copp_police.group(4)
            conform=copp_police.group(5)
            conform_value=copp_police.group(6)
            violate=copp_police.group(7)
            violate_value=copp_police.group(8)
            if cir:
                pmap_dict[(ptype,pmap)][(ctype,cmap)].update({cir : cir_value})
            if bc:
                pmap_dict[(ptype,pmap)][(ctype,cmap)].update({bc : bc_value})
            if conform:
                 pmap_dict[(ptype,pmap)][(ctype,cmap)].update({conform : conform_value})
            if violate:
                 pmap_dict[(ptype,pmap)][(ctype,cmap)].update({violate : violate_value})
    return pmap_dict
    

def clearConsole(log, *args):
    '''Clear the console line of given ip and port.

    Returns False if fails, True if succeeds

    Usage:
     status=clearConsole(log,'-ip 172.23.40.209 -port 2001')
    '''

    arggrammar={}
    arggrammar['ip']='-type str -required True'
    arggrammar['port']='-type int -required True'
    arggrammar['username']='-type str -default admin'
    arggrammar['password']='-type str -default insieme'
    arggrammar['svrType']='-type str -default cisco'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return False

    ip=options_namespace.ip
    port=str(options_namespace.port)
    username=options_namespace.username
    password=options_namespace.password
    svrType=options_namespace.svrType

    if len(port)==4:
        port=port[2:4]

    login_patterns=[                 \
          '[lL]ogin[ ]*:',                  \
          '[uU]ser[ ]*[Nn]ame[ ]*:',             \
          '[Pp]assword[ ]*:',                \
          '>$',                       \
          '>>$',                       \
          '#',                      \
          'Connection refused',      \
          pexpect.EOF,               \
          pexpect.TIMEOUT            \
    ]

    hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
    done=False
    max_connect_retry=3
    connect_retry=0
    while not done:
        i=hdl.expect(login_patterns,timeout=30)
        print(hdl.before + str(hdl.after))
        if i==0:
            # Login:
            hdl.send('{0}\r'.format(username))
        elif i==1:
            # User Name :
            hdl.send('{0}\r'.format(username))
        elif i==2:
            # Password:
            hdl.send('{0}\r'.format(password))
        elif i==3:
            # > prompt
            hdl.send('enable\r')
        elif i==4:
            # >> prompt for cyclades
            print("Inside cyclades login prompt;sending clear line")
            hdl.send('clear line {0}\r'.format(port))
            hdl.expect('>>')
            time.sleep(0.2)
            print(hdl.before + str(hdl.after))

            done=True
        elif i==5:
            # # prompt
            if svrType=='cisco':
                hdl.send('clear line {0}\r'.format(port))
                hdl.expect('\[confirm\]')
                time.sleep(0.2)
                print(hdl.before + str(hdl.after))
                hdl.send('\r')

                done=True
            else:
                # For cyclades need to enter config mode
                print("Inside cyclades login prompt;sending config")
                hdl.send('config\r')
        elif i==6:
            # Connection refused
            log.error('Connection refused to termserv {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection refused to termserv {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            if connect_retry == max_connect_retry:
                return False
            print('Retrying...')
            log.info('Retrying...')
            time.sleep(10)
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
            done=False
        elif i==7:
            # EOF
            log.error('Connection failed to termserv {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection failed to termserv {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            if connect_retry == max_connect_retry:
                return False
            print('Retrying...')
            log.info('Retrying...')
            time.sleep(10)
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
            done=False
        elif i==8:
            # timedout
            log.error('Connection failed to termserv {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection failed to termserv {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            if connect_retry == max_connect_retry:
                return False
            print('Retrying...')
            log.info('Retrying...')
            time.sleep(10)
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
            done=False

    hdl.send('exit\r')
    hdl.terminate(force=True)
    return True


def changeConsoleSpeed(log, *args):
    '''Change the console speed for given ip and port.

    Returns False if fails, True if succeeds

    Usage:
     status=changeConsoleSpeed(log,'-ip 172.23.40.209 -port 2001 -speed 115200')
    '''

    arggrammar={}
    arggrammar['ip']='-type str -required True'
    arggrammar['port']='-type int -required True'
    arggrammar['username']='-type str -default admin'
    arggrammar['password']='-type str -default insieme'
    arggrammar['speed']='-type int -default 9600'

    options_namespace=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options_namespace.VALIDARGS:
        log.warning('Invalid arguments')
        return False

    ip=options_namespace.ip
    port=str(options_namespace.port)
    username=options_namespace.username
    password=options_namespace.password

    if len(port)==4:
        port=port[2:4]

    login_patterns=[                 \
          'Login:',                  \
          'User Name :',             \
          'Username:',               \
          'Password',                \
          '>',                       \
          '#$',                      \
          'Connection refused',      \
          pexpect.EOF,               \
          pexpect.TIMEOUT            \
    ]

    hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
    done=False
    max_connect_retry=10
    connect_retry=0
    while not done:
        i=hdl.expect(login_patterns,timeout=30)
        print(hdl.before + str(hdl.after))
        if i==0:
            # Login:
            hdl.send('{0}\r'.format(username))
        elif i==1:
            # User Name :
            hdl.send('{0}\r'.format(username))
        elif i==2:
            # Username:
            hdl.send('{0}\r'.format(username))
        elif i==3:
            # Password:
            hdl.send('{0}\r'.format(password))
        elif i==4:
            # > prompt
            hdl.send('enable\r')
        elif i==5:
            # # prompt
            hdl.send('configure terminal\r')
            time.sleep(0.2)
            hdl.send(' line {0}\r'.format(port))
            time.sleep(0.2)
            hdl.send(' speed {0}\r'.format(options_namespace.speed))
            time.sleep(0.2)
            print(hdl.before + str(hdl.after))
            hdl.send('\r')
            hdl.expect('#')
            print(hdl.before + str(hdl.after))
            done=True
        elif i==6:
            # Connection refused
            log.error('Connection refused to termserv {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection refused to termserv {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            if connect_retry == max_connect_retry:
                return False
            print('Retrying...')
            log.info('Retrying...')
            time.sleep(10)
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
            done=False
        elif i==7:
            # EOF
            log.error('Connection failed to termserv {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection failed to termserv {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            if connect_retry == max_connect_retry:
                return False
            print('Retrying...')
            log.info('Retrying...')
            time.sleep(10)
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
            done=False
        elif i==8:
            # timedout
            log.error('Connection failed to termserv {0}'.format(ip))
            print('\n\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print('Connection failed to termserv {0}'.format(ip))
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n')
            if connect_retry == max_connect_retry:
                return False
            print('Retrying...')
            log.info('Retrying...')
            time.sleep(10)
            connect_retry+=1
            hdl=pexpect.spawn('telnet {0}'.format(ip),timeout=30)
            done=False

    hdl.send('exit\r')
    hdl.terminate(force=True)
    return True

def getStatsForACLEntry(hdl,log,*args):
        """Added by sandesub
        This method returns the count for a given ACL entry with input as acl_name and seq_no
        """
        arggrammer={}
        arggrammer['type']='-type str -required True -choices ["ip","ipv6","mac","vlan"]'
        arggrammer['acl_name']='-type str'
        arggrammer['seq_no']=' -type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
        if ns.type == "ip":
            sw_cmd="show ip access-lists " + ns.acl_name + " "  + "| grep " + ns.seq_no
        if ns.type == "ipv6":
            sw_cmd="show ipv6 access-lists " + ns.acl_name + " "  + "| grep " + ns.seq_no
        if ns.type == "mac":
            sw_cmd="show mac access-lists " + ns.acl_name + " "  + "| grep " + ns.seq_no
        if ns.type == "vlan":
            sw_cmd="show vlan access-list " + ns.acl_name + " "  + "| grep " + ns.seq_no
        output = hdl.execute(sw_cmd)
        pattern = ".*\[match="
        pattern = pattern+"("+rex.NUM+")"
        pattern = pattern+"\]"
        count=re.findall(pattern,output)
        if count == []: 
            log.info('Stats not enabled correctly') 
            return -1
        else:
            return count[0]  

def clearACLStats(hdl,log,*args):
        """Added by sandesub
        This method clears the ACL stats for all ACLs (default) or a given ACL
        """
        arggrammar={}
        arggrammar['acl_name']='-type str'
        arggrammar['type']='-type str -required True -choices ["ip","ipv6","mac","vlan"]'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
        if ns.acl_name:
            sw_cmd="clear {0} access-list counters ".format(ns.type) + ns.acl_name 
        else:
            sw_cmd="clear {0} access-list counters".format(ns.type) 
        hdl.execute(sw_cmd)

def copyRunningToStartup(hdl,log):
        """Added by sandesub
        This method copies the running-config to startup config
        """
        sw_cmd="copy running-config startup-config" 
        hdl.execute(sw_cmd)
       
                
def clearInterfaceConfig(hdl,log,*args):
    '''Unconfigure commands under a given interface.

    Usage:
      clearInterfaceConfig(hdl,log,'-interface eth1/1-3,eth1/5')
      clearInterfaceConfig(hdl,log,'-interface all')
      clearInterfaceConfig(hdl,log,'-interface all -skip_fex_fabric')
      clearInterfaceConfig(hdl,log,'-interface eth1/1,po10-11,vlan10 -skip_po_members')

     - Physical interface config are cleared 
     - Logical interfaces are deleted. Ex: Loopback, SVI, and Port-channel
     - PO member configurations are also cleared
     - mgmt interface is not changed
     - If skip_fex_fabric option is used, fabric PO and member interfaces remain untouched
     - If skip_po_members option is used, the specified PO member configs remain untouched
    '''

    arggrammar={}
    arggrammar['interface']='-type str -format {0}|all -required True'.format(rex.INTERFACE_RANGE)
    arggrammar['skip_fex_fabric']='-type bool'
    arggrammar['skip_po_members']='-type bool'
    #arggrammar['skip_fex_fabric']='-type bool -dependency [("interface","==","all")]'

    options=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not options.VALIDARGS:
        log.error('Invalid arguments')
        return

    run_config=''
    if options.interface=='all':
        run_config=getRunningConfig(hdl,log)

    # Gather fex fabric info
    fabric_intf_list=[]
    if options.skip_fex_fabric:
        show_output=hdl.execute('show interface fex-fabric')
        fabric_intf_list=re.findall('^[0-9]+[ \t]+({0})[ \t]+'\
            .format(rex.PHYSICAL_INTERFACE_NAME),show_output,re.M)
        # Get the relevent port-channels
        po_intfs=[]
        for intf in fabric_intf_list:
            if options.interface=='all':
                intf_config=''.join(re.findall('^interface {0}(?![0-9]).*?\n(?=[^ \t])'\
                    .format(getFullInterfaceName(log,intf)),run_config,re.I|re.M|re.DOTALL))
            else:
                intf_config=getRunningConfig(hdl,log,'-interface {0}'.format(intf))
            search=re.search('channel-group[ \t]+([0-9]+)',intf_config)
            if search:
                po_intfs.append('Po'+str(search.group(1)))
        po_intfs=list(set(po_intfs))
        fabric_intf_list.extend(po_intfs)

    delete_intf_list=[]
    if options.interface=='all':
        i_list=getInterfaceList(hdl,log)
    else:
        i_list=strtoexpandedlist(options.interface)

    i_list=filter(re.compile('^(?!mgmt)').search,i_list)
    if not options.skip_fex_fabric:
        # Skip FEX port since we would have wiped out the fabric and fex would go offline
        i_list=filter(re.compile('^(?!Eth[0-9]{3}/[0-9]/[0-9]+)').search,i_list)
    delete_intf_list=filter(re.compile('^(?:Lo|Po|Vlan)',re.I).search,i_list)
    i_list=filter(re.compile('^(?!Lo|Po|Vlan)',re.I).search,i_list)

    po_members_list=[]
    for po_intf in filter(re.compile('^(?:Po)',re.I).search,delete_intf_list):
        po_members_list.extend(getPortChannelMemberList(hdl,log,'-pc_nam {0}'.format(po_intf)))

    intf_list=getFullInterfaceName(log,i_list)

    # If we are not skipping the cleanup of members, then add members to intf_list for cleanup
    if not options.skip_po_members:
        intf_list.extend(po_members_list)
        po_members_list=[]

    delete_intf_list=getFullInterfaceName(log,delete_intf_list)
    po_members_list=getFullInterfaceName(log,po_members_list)
    fabric_intf_list=getFullInterfaceName(log,fabric_intf_list)

    try:
        index=delete_intf_list.index('Vlan1')
        delete_intf_list.pop(index)
        intf_list.append('Vlan1')
    except:
        pass

    for intf in intf_list:
        if intf in fabric_intf_list:
            continue
        if intf in po_members_list:
            continue
        if options.interface=='all':
            # Extract relevent interface config here from run_config
            intf_config=''.join(re.findall('^interface {0}(?![0-9]).*?\n(?=[^ \t])'\
                .format(intf),run_config,re.I|re.M|re.DOTALL))
        else:
            intf_config=getRunningConfig(hdl,log,'-interface {0}'.format(intf))
        config_list=[]
        for cmd in intf_config.split('\r\n'):
            if cmd.strip():
                config_list.append(cmd.strip())
        if len(config_list)<=1:
            continue
        unconfig_list=[]
        for cmd in config_list[1:]:
            if cmd:
                if re.search('^no ',cmd):
                    unconfig_list.append(re.sub('^no ','',cmd))
                else:
                    unconfig_list.append('no ' + cmd)
        unconfig_list.reverse()
        intf_cmd=config_list[0]
        unconfig_list.insert(0,intf_cmd)
        hdl.execute('config t')
        for cmd in unconfig_list:
            done=0
            while not done:
                cmd_response=hdl.execute(cmd)
                if re.search('Invalid command',cmd_response,re.I):
                    cmd_list=cmd.split()
                    cmd=' '.join(cmd_list[:-1])
                else:
                    done=1
        hdl.execute('end')
    for intf in delete_intf_list:
        if intf in fabric_intf_list:
            continue
        hdl.iconfig('no interface {0}'.format(intf))
    return 'True'

# Usage
#   subnet('192.168.2.1','255.255.255.0')
# Returns
#   '192.168.2.0' 
def subnet(ipaddr,netmask):
 
    ipaddr=ipaddr.split(".")
    netmask=netmask.split(".")
    subnet = [str(int(ipaddr[x]) & int(netmask[x])) for x in range(0,4)]
    return ".".join(subnet)

def getDeviceFreeSpace(hdl,log,*args):
    device_pattern='[a-zA-Z]+\:'
    arggrammar={}
    arggrammar['device']='-type str -default bootflash:'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not ns.VALIDARGS:
        log.error('Invalid arguments')
        return
    
    pattern=" *("+rex.NUM+") *bytes *free"

    cmd="dir {0} | inc free".format(ns.device)
    show_out=hdl.execute(cmd)

    result=re.search(pattern,show_out,re.I)
    if result:
        return result.group(1) 
    else:
        return -1

def deleteFilesFromBootflash(hdl,log,*args):
    arggrammar={}
    arggrammar['file_pattern']='-type str'.format(rex.INTERFACE_RANGE)
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not ns.VALIDARGS:
        log.error('Invalid arguments')
        return


    if ns.file_pattern:
        cmd='dir bootflash: | inc {0}'.format(ns.file_pattern)
    else:
        ### find the device type
        if hdl.device_type in ['EOR','sTOR']:
            image_type=inseor
        elif hdl.device_type in ['N7k']:
            image_type=n7000
        elif hdl.device_type in ['N3k']:
            image_type=n3000
        else:
            image_type=n5000

        cmd='dir bootflash: | inc {0}'.format(image_type)

    show_out=hdl.execute(cmd)
    file_pat=rex.NUM+"[\s]+("+rex.MONTH+")[\s]+"+"[0-3][0-9][\s]+"+rex.CLOCK_TIME+"[\s]+"
    file_pat+=rex.YEAR+"[\s]+ ([\S]+)"

    for line in show_out.split('\n'):
        if re.search('do-not-delete',line,re.I):
            continue
        if re.search('golden',line,re.I):
            continue
        if re.search('dplug',line,re.I):
            continue
        ### if the file is directory then skip it
        if re.search("\/",line):
            continue

        result=re.search(file_pat,line,re.I)
        if result:
            file_name=result.group(2)
            log.info('Deleting file {0} from bootflash'.format(file_name))
            cmd='delete bootflash:{0} no-prompt'.format(file_name)
            hdl.execute(cmd)

def checkAndFreeSpaceFromDevice(hdl,log,*args):

    device_pattern='[a-zA-Z]+\:'
    arggrammar={}
    arggrammar['device']='-type str -format {0} -default bootflash:'.format(device_pattern)
    arggrammar['file_pattern']='-type str'
    arggrammar['space']='-type int'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')

    if not ns.VALIDARGS:
        log.error('Invalid arguments')
        return

    if ns.space:
        ### check if the required space is already there.
        ### if so, then return, otherwise delete some files
        ### based on file pattern/default

        space=int(getDeviceFreeSpace(hdl,log, '-device {0}'.format(ns.device)))
        if space==-1:
            log.error('Failed to get free space for device {0}'.format(ns.device))
            return -1
        elif space > ns.space:
            log.info('Device {0} has more free space as required'.format(ns.device))
            log.info('{0} :: {1}'.format(space, ns.space))
            return 1
        else:
            log.info('Need to cleanup some files from device {0}'.format(ns.device))
    else:
        log.info('Need to cleanup some files from device {0}'.format(ns.device))

    if ns.file_pattern:
        deleteFilesFromBootflash(hdl, log, '-file_pattern {0}'.format(ns.file_pattern)) 
    else:
        deleteFilesFromBootflash(hdl, log)

    return 1
        
def clearStaleConfig(hdl,log,*args):

    '''Unconfigure stale/pending conigs on switch

    Usage:
      clearStaleConfig(hdl,log,'-vlan  -routing')
      clearStaleConfig(hdl,log,'-all')

    If option "-all" is used, all configs are cleaned, else only specific section
    is cleaned. default is all.
    This will be expanded to add more sections.
    '''

    arggrammar={}
    arggrammar['vlan']='-type bool -default False'
    arggrammar['routing']='-type bool -default False'
    arggrammar['all']='-type bool -default False'

    options=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if not args:
        options.all = True

    if (options.all) or options.vlan:
        vlans = getVlanList(hdl,log)
        log.debug ('Cleaning vlans on {0}'.format(hdl.switchName))
        hdl.iconfig ('no vlan {0}'.format(listtostr(vlans)))
        
    if (options.all) or options.routing:
        # will expand to clear routing
        log.debug ('Cleaning routing on {0}'.format(hdl.switchName))

#
# Consider a flow_stat_dict as follows
# input_dict={('eth1', 'ABCD', 900, 100, 2, '00:00:01:02:03:04','00:00:02:03:04:05','1.1.1.1','2.2.2.2'): 1, 
#             ('eth1', 'ABCD', 900, 100, 2, '00:00:01:02:03:04','00:00:02:03:04:05','1.1.1.1','2.2.2.3'): 1,
#             ('eth1', 'BCDE', 900, 100, 2, '00:00:01:02:03:04','00:00:02:03:04:05','1.1.1.1','2.2.2.3'): 1}
# key is tuple of the form as follows
#   ('interface','pgid','outervlan','innervlan','cos','srcmac','dstmac','srcip','dstip')
#
# If we need to sum all the entries matching only interface='eth1' & pgid='ABCD'
#
# Then we can use this function with the call as follows which will return  2 in the above example
#
# sumwildcardkeys( inputdict, ('interface','pgid','outervlan','innervlan','cos','srcmac','dstmac','srcip','dstip'), \
#     {'interface': 'eth1', 'pgid': 'ABCD'})
#
# 

def sumWildCardKeys( inputdict, keyfields, subkeydict ):
    key_to_be_matched=[]
    for key in keyfields:
        if key not in subkeydict.keys():
            key_to_be_matched.append('WILDCARD')
        else:
            key_to_be_matched.append(subkeydict[key])
    returnval=0
    for key in inputdict.keys():
        keymatched=True
        for index in range(len(key)):
            if key_to_be_matched[index] != 'WILDCARD' and key_to_be_matched[index] != key[index]:
                keymatched=False
        if keymatched:
            returnval=returnval+inputdict[key]
    return returnval

def getWildCardkeys( inputdict, keyfields, subkeydict):

    key_to_be_matched=[]
    for key in keyfields:
        if key not in subkeydict.keys():
            key_to_be_matched.append('WILDCARD')
        else:
            key_to_be_matched.append(subkeydict[key])


    returnkeys=[]
    for key in inputdict.keys():
        keymatched=True
        for index in range(len(key)):
            if key_to_be_matched[index] != 'WILDCARD' and key_to_be_matched[index] != key[index]:
                keymatched=False
        if keymatched:
            returnkeys.append(key)

    return returnkeys 

# Use this proc to create a subset from an existing dict
# For e.g originaldict={1:'a',2:'b',3:'c',4:'d'}
# If we need to create another dict x={1:'a',2:'b'}
# We can call subDict(originaldict,[1,2])
# Removekeys is useful when only few keys need to removed,
# This is useful only when few feys need to be copied 
   
def subDict(originaldict,keys):

    #tbr
    #print '---------------------------------------------------------------------------------------'
    #print originaldict
    #print keys
    #print '---------------------------------------------------------------------------------------'
    returndict={}
    for key in keys:
        returndict[key]=originaldict[key]
    return returndict 

# Same usecase as subDict but can do at multiple leves
# For e.g if dict is as follows
# originaldict={11: {1: 'a', 2: 'aa', 3: 'aaa'}, 22: {2: 'b'}, 33: {3: 'c'}, 44: {4: 'd'}}
# and if we need to keep only 1 under 1st level key 11, then we need to call as follows
# eor_utils.multiLevelSubDict(originaldict,2,11,[1])


def multiLevelSubDict(originaldict,level,superkey,subkeys):

    returndict={}
    for key in originaldict.keys():
        if level == 2:
            if key == superkey:
                returndict[key]=subDict(originaldict[key],subkeys)
            else: 
                returndict[key]=originaldict[key]
        else:
            returndict[key]=multiLevelSubDict(originaldict[key],level-1,superkey,subkeys)

    return returndict







class createBcmTableObject(object):

    """ Class to parse the broadcom table outputs and convert to dictionary format. Expects the
    input as 'Index: <Row>' where the <Row> is in key value pairs separated by commas"""

    def __init__( self, bcm_cmd_dump ):

       import re

       self.table=collections.OrderedDict()

       table_rows=bcm_cmd_dump.split('\n')
       for row in table_rows:
          (row_key, row_value)=row.split(':')
          value_row=row_value.rstrip('\r').lstrip('<').rstrip('>')
          self.table[row_key]=collections.OrderedDict()
          for data_params in value_row.split(','):
             (data_key,data_value)=data_params.split('=')
             self.table[row_key][data_key]=data_value
       print('Table Data', self.table )



def collectTechSupport( hdl, log, *args ):

    """ Method to capture tech support on NXOS switches using an icon handle. The default timeout value is 
    900 secs. The destination URI can be bootflash or a remote location. If the destination URI is a remote
    location using scp/sftp/ftp/tftp we first capture the tech support to bootflash and copy it out using
    icon.icopy"""

    arggrammar={}
    arggrammar['timeout']='-type int -default 900'
    arggrammar['detail']='-type bool -default False'
    arggrammar['component']='-type str'
    arggrammar['destination_uri']='-type str -default bootflash:tech_support'

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    cmd='show tech-support '

    if ns.component:
       cmd = cmd + ns.component

    if ns.detail:
       cmd = cmd + ' detail'

    if re.search( 'scp|sftp|ftp|tftp', ns.destination_uri, re.I ):
        cmd = cmd + ' > ' + ' bootflash:tech_supp999'
    else:
        cmd = cmd + ' > ' + ns.destination_uri

    print(cmd)
    hdl.hdl.sendline(cmd)
    i=hdl.hdl.expect(['#','yes/no'],timeout=ns.timeout)

    if i == 1:
        hdl.hdl.sendline("yes")
        i=hdl.hdl.expect(['#','y/n'],timeout=ns.timeout)
        if i == 1:
           hdl.hdl.sendline("y")
           i=hdl.hdl.expect(['#'],timeout=ns.timeout)

    
    if re.search( 'scp|sftp|ftp|tftp', ns.destination_uri, re.I ):
        hdl.icopy( 'bootflash:tech_supp999', ns.destination_uri ) 

    
def getFdDict(hdl,log,*args):
    ''' Method to fetch all the open file descriptors on a given module 
        defaults to SUP if module argument is not specified. 
        It uses lsof and constructs a dictionary of Fd count for all 
        processes running on the system and returns it'''

    arggrammar={}
    arggrammar['module']='-type str'
    arggrammar['fex']='-type str'
    arggrammar['debug_plugin']='-type str'
    arggrammar['total_only']='-type bool'

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    fd_dict={}

    if not ns.VALIDARGS:
        log.info('Invalid arguments- module or debug_plugin needed')
        return fd_dict

    debug_plugin=ns.debug_plugin

    if not debug_plugin:
        debug_plugin=hdl.testbed_info.debug_plugin[hdl.device_type]

    debug_plugin=re.sub('^bootflash:/*','',debug_plugin)

    if ns.module:
        module_list=strtoexpandedlist(ns.module)
    else:
        module_list=[]

    if ns.fex:
        fex_list=strtoexpandedlist(ns.fex)
    else:
        fex_list=[]

    if hdl.device_type == 'sTOR':
        active_sup_slot='1'
    elif hdl.device_type == 'EOR':
        active_sup_slot=getSupervisorSlotNumber(hdl,log)

    module_list.append(active_sup_slot)
    module_list=list(set(module_list))

    fd_total_cmd='/usr/sbin/lsof | wc -l'

    time_now=int(time.time())
    for module in module_list:
        fd_dict[module]={}
        if module == active_sup_slot:
            total_fd_out=hdl.bashexec(fd_total_cmd,'-debug_plugin {0}'.format(debug_plugin))
        else:
            total_fd_out=hdl.bashexec(fd_total_cmd,'-debug_plugin {0} -module {1}'.format(debug_plugin,module))
          
        match=re.search('([0-9]+)',total_fd_out,re.I)
        if not match:
            testResult('fail','Could not get total FD count on {0} module {1}'.format(hdl.switchName,module),log)
            return
        fd_dict[module]['total']=match.group(1)
        if not ns.total_only:

            # TODO make the identifier a integer seed and keep track of it
            if module == active_sup_slot:
                hdl.execute('mkdir bootflash:fdleak')
                hdl.execute('mkdir bootflash:fdleak/{0}'.format(time_now))
                hdl.execute('mkdir bootflash:fdleak/{0}/{1}'.format(time_now,active_sup_slot))
                fd_detail_cmd='cd /proc; for f in `ls -d [0-9]*`; do echo \"$f `/usr/sbin/lsof -p $f | /usr/bin/tee /bootflash/fdleak/{0}/{1}/$f | wc -l` `ps -o %a $f | sed 1d | cut -d\" \" -f1`\"; done'.format(time_now,active_sup_slot)
                proc_ls_out=hdl.bashexec(fd_detail_cmd,'-debug_plugin {0}'.format(debug_plugin))
            else:
                hdl.execute('mkdir bootflash:fdleak')
                hdl.execute('mkdir bootflash:fdleak/{0}'.format(time_now))
                hdl.execute('mkdir bootflash:fdleak/{0}/{1}'.format(time_now,module))
                hdl.bashexec('mkdir /bootflash/fdleak; mkdir /bootflash/fdleak/{0}'.format(time_now),'-debug_plugin {0} -module {1}'.format(debug_plugin,module))
                fd_detail_cmd='cd /proc; for f in `ls -d [0-9]*`; do echo \"$f `/usr/sbin/lsof -p $f | /usr/bin/tee /bootflash/fdleak/{0}/$f | wc -l` `ps -o %a $f | sed 1d | cut -d\" \" -f1`\"; done'.format(time_now)
                proc_ls_out=hdl.bashexec(fd_detail_cmd,'-debug_plugin {0} -module {1}'.format(debug_plugin,module))
                hdl.bashexec('copy_to_sup \"/bootflash/fdleak/{0}/*\" /bootflash/fdleak/{0}/{1}/;rm -rf /bootflash/fdleak/{1}'.format(time_now,module),'-debug_plugin {0} -module {1}'.format(debug_plugin,module))

            proc_fd_name=re.findall('([0-9]+) ([0-9]+) (\S+)',proc_ls_out)
            for proc_id,fd_count,proc_descr in proc_fd_name:
                fd_dict[module][(proc_id,proc_descr)]=fd_count

    for fex in fex_list:
        fd_dict[fex]={}
        total_fd_out=hdl.bashexec(fd_total_cmd,'-debug_plugin {0} -fex {1}'.format(debug_plugin,fex))
        match=re.search('([0-9]+)',total_fd_out,re.I)
        if not match:
            testResult('fail','Could not get total FD count on {0} fex {1}'.format(hdl.switchName,fex),log)
            return
        fd_dict[fex]['total']=match.group(1)
        if not ns.total_only:
            fd_detail_cmd='cd /proc; for f in `ls -d [0-9]*`; do echo \"$f `/usr/sbin/lsof -p $f | wc -l` `ps -o %a $f | sed 1d | cut -d\" \" -f1`\"; done'.format(time_now)
            proc_ls_out=hdl.bashexec(fd_detail_cmd,'-debug_plugin {0} -fex {1}'.format(debug_plugin,fex))
            proc_fd_name=re.findall('([0-9]+) ([0-9]+) (\S+)',proc_ls_out)
            for proc_id,fd_count,proc_descr in proc_fd_name:
                fd_dict[fex][(proc_id,proc_descr)]=fd_count

    return fd_dict


def compareFdDicts( log, dict_before, dict_after, threshold ):
     if int(dict_before['total']) != int(dict_after['total']):
         fd_diff=int(dict_after['total']) - int(dict_before['total'])
         if fd_diff > threshold:
             msg='There is some File descriptor leak. ' +\
                 'The total number of FDs before {0} and after {1} is more than the given threshold {2}'\
                 .format( dict_before['total'], dict_after['total'], threshold )
             print(msg)
             testResult( 'fail', msg, log )
             compareVars( dict_before, dict_after, log, '-equal -allfailures')
     else:
         msg='The total number of FDs before {0} and after {1} is less than the threshold {2}'\
             .format( dict_before['total'], dict_after['total'], threshold )
         print(msg)
         log.info(msg)


def getDfDict(hdl,log,*args):
    ''' Returns a dict for output of df- disk usage on sup or line card/FM/SC/fex card based on module number
    if no module number is given, gets df on active sup by loading debug plugin
    Sample Usage: 
        getDfDict(hdl, log, '-debug_plugin ins-dp')
        getDfDict(hdl, log, '-module 3')
    '''

    arggrammar={}
    arggrammar['module']='-type str'
    arggrammar['fex']='-type str'
    arggrammar['debug_plugin']='-type str'

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    df_dict={}

    if not ns.VALIDARGS:
        log.info('Invalid arguments- module or debug_plugin needed')
        return df_dict

    debug_plugin=ns.debug_plugin

    if not debug_plugin:
        debug_plugin=hdl.testbed_info.debug_plugin[hdl.device_type]

    debug_plugin=re.sub('^bootflash:/*','',debug_plugin)

    if ns.module:
        module_list=strtoexpandedlist(ns.module)
    else:
        module_list=[]

    if ns.fex:
        fex_list=strtoexpandedlist(ns.fex)
    else:
        fex_list=[]

    if hdl.device_type == 'sTOR':
        active_sup_slot='1'
    elif hdl.device_type == 'EOR':
        active_sup_slot=getSupervisorSlotNumber(hdl,log)
    #module_list.append(active_sup_slot)
    module_list=list(set(module_list))

    df_cmd='df'
    pat='([a-zA-Z0-9/]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+%)[ \t]+([A-Za-z0-9/-_]+)\r\n'

    for module in module_list:
        df_dict[module]={}
        if module == active_sup_slot:
            df_out=hdl.bashexec(df_cmd,'-debug_plugin {0}'.format(debug_plugin))
        else:
            df_out=hdl.bashexec(df_cmd,'-debug_plugin {0} -module {1}'.format(debug_plugin,module))
          
        df_list=re.findall(pat, df_out)

        if not df_list:
            testResult('fail','Could not get DF data on {0} module {1}'.format(hdl.switchName,module),log)
            return

        df_dict[module]=convertListToDict(df_list,['Filesystem','1K_blocks','Used','Available','Use%','Mounted_on'],'Mounted_on')

    for fex in fex_list:
        df_dict[fex]={}
        df_out=hdl.bashexec(df_cmd,'-debug_plugin {0} -fex {1}'.format(debug_plugin,fex))

        df_list=re.findall(pat, df_out)

        if not df_list:
            testResult('fail','Could not get DF data on {0} fex {1}'.format(hdl.switchName,fex),log)
            return

        df_dict[fex]=convertListToDict(df_list,['Filesystem','1K_blocks','Used','Available','Use%','Mounted_on'],'Mounted_on')

    return df_dict


def compareDfDicts( log, dict_before, dict_after, threshold , *args):

    arggrammar={}
    arggrammar['switch_id']='-type str'
    arggrammar['module']='-type str'
    arggrammar['mutualInclusive'] =[('switch_id','module')]
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if not ns.VALIDARGS:
        log.info('Invalid arguments')
        return 

    for dir in dict_after.keys():
         if int(dict_before[dir]['Used']) != int(dict_after[dir]['Used']):
             df_diff=int(dict_after[dir]['Used']) - int(dict_before[dir]['Used'])
             if df_diff > threshold:
                 if ns.switch_id:
                     msg='Partition size of {0} crossed threshold on {4} module {5}. Before:{1} After:{2} Threshold:{3}'\
                         .format(dir, dict_before[dir]['Used'], dict_after[dir]['Used'], threshold, ns.switch_id, ns.module)
                     resourceMon.df_result.update({ns.switch_id:{ns.module:'fail'}})
                 else:
                     msg='Partition size of {0} crossed threshold. Before:{1} After:{2} Threshold:{3}'\
                         .format(dir, dict_before[dir]['Used'], dict_after[dir]['Used'], threshold )
                 print(msg)
                 testResult('fail', msg,log)
                 compareVars( dict_before, dict_after, log, '-allfailures')
         else:
             msg='The disk usage of file system {0} before {1} and after {2} is less than the threshold {3}'\
                 .format( dir, dict_before[dir]['Used'], dict_after[dir]['Used'], threshold )
             print(msg)
             log.info(msg)


def getTmpLogsDict(hdl,log,*args):
    ''' Returns a dict for output of ls -l /tmp/logs/ or any other logs directory given on sup or line card/FM/SC card based on module number
    if no module number is given, gets ls -l  on active sup by loading debug plugin
    Sample Usage: 
        getTmpLogsDict(hdl, log, '-debug_plugin ins-dp')
        getTmpLogsDict(hdl, log, '-module 3')
    '''

    arggrammar={}
    arggrammar['module']='-type str'
    arggrammar['fex']='-type str'
    arggrammar['debug_plugin']='-type str'
    arggrammar['logs_dir']='-type str -default /tmp/logs/'

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    ls_dict={}

    if not ns.VALIDARGS:
        log.info('Invalid arguments- module or debug_plugin needed')
        return ls_dict

    debug_plugin=ns.debug_plugin

    if not debug_plugin:
        debug_plugin=hdl.testbed_info.debug_plugin[hdl.device_type]

    debug_plugin=re.sub('^bootflash:/*','',debug_plugin)

    if ns.module:
        module_list=strtoexpandedlist(ns.module)
    else:
        module_list=[]

    if ns.fex:
        fex_list=strtoexpandedlist(ns.fex)
    else:
        fex_list=[]

    if hdl.device_type == 'sTOR':
        active_sup_slot='1'
    elif hdl.device_type == 'EOR':
        active_sup_slot=getSupervisorSlotNumber(hdl,log)
    #module_list.append(active_sup_slot)
    module_list=list(set(module_list))

    ls_cmd='ls -l {0}'.format(ns.logs_dir)

    pat='([rwx-]+)\s+[0-9]+\s+({0})\s+({0})\s+([0-9]+)\s+([a-zA-Z]+\s+[0-9]+)\s+([0-9:]+)\s+({0})'.format(rex.ALPHANUMSPECIAL)

    for module in module_list:
        ls_dict[module]={}
        if module == active_sup_slot:
            ls_out=hdl.bashexec(ls_cmd,'-debug_plugin {0}'.format(debug_plugin))
        else:
            ls_out=hdl.bashexec(ls_cmd,'-debug_plugin {0} -module {1}'.format(debug_plugin,module))
          
        ls_list=re.findall(pat, ls_out)

        if not ls_list:
            log.info('File info unavailable on {0} module {1} for {2}'.format(hdl.switchName,module,ns.logs_dir))
            return ls_dict

        ls_dict[module]=convertListToDict(ls_list,['Permissions','User','Group','Size','Date','Time','File_name'],'File_name')

    for fex in fex_list:
        ls_dict[fex]={}
        ls_out=hdl.bashexec(ls_cmd,'-debug_plugin {0} -fex {1}'.format(debug_plugin,fex))

        ls_list=re.findall(pat, ls_out)

        if not ls_list:
            log.info('File info unavailable on {0} fex {1} for {2}'.format(hdl.switchName,fex,ns.logs_dir))
            return ls_dict

        ls_dict[fex]=convertListToDict(ls_list,['Permissions','User','Group','Size','Date','Time','File_name'],'File_name')

    return ls_dict


def compareTmpLogsDicts( log, dict_before, dict_after, threshold, *args):

    arggrammar={}
    arggrammar['switch_id']='-type str'
    arggrammar['module']='-type str'
    arggrammar['mutualInclusive'] =[('switch_id','module')]
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if not ns.VALIDARGS:
        log.info('Invalid arguments')
        return 

    if len(dict_after) - len(dict_before) > 20:
        if ns.switch_id:
            msg='Number of files in {0} on {1} module {2} crossed threshold. Before:{3} After:{4} Threshold:{5}'\
                .format('tmp/logs',ns.switch_id,ns.module,len(dict_before),len(dict_after),20)
        else:
            msg='Number of files in {0} crossed threshold. Before:{1} After:{2} Threshold:{3}'\
                .format('tmp/logs',len(dict_before),len(dict_after),20)
        print(msg)
        testResult('fail',msg,log)
    for logfile in dict_after.keys():
         if int(dict_before[logfile]['Size']) != int(dict_after[logfile]['Size']):
             log_diff=int(dict_after[logfile]['Size']) - int(dict_before[logfile]['Size'])
             if log_diff > threshold:
                 if ns.switch_id:
                     msg='File size of {0} crossed threshold on {4} module {5}. Before:{1} After:{2} Threshold:{3}'\
                         .format( logfile, dict_before[logfile]['Size'], dict_after[logfile]['Size'], threshold, ns.switch_id, ns.module)
                     resourceMon.ls_result.update({ns.switch_id:{ns.module:'fail'}})
                 else:
                     msg='File size of {0} crossed threshold. Before:{1} After:{2} Threshold:{3}'\
                         .format( logfile, dict_before[logfile]['Size'], dict_after[logfile]['Size'], threshold )
                 print(msg)
                 testResult('fail',msg,log)
                 compareVars( dict_before, dict_after, log, '-allfailures')
         else:
             msg='The log file {0} size difference before {1} and after {2} is less than the threshold {3}'\
                 .format( logfile, dict_before[logfile]['Size'], dict_after[logfile]['Size'], threshold )
             print(msg)
             log.info(msg)


def getSysmgrConfigFilesDict( hdl, log, *args ):
    
    arggrammar={}
    arggrammar['module']='-type int'
    arggrammar['debug_plugin']='-type str'

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    sysmgr_conf_dict={}

    if ns.module and ns.debug_plugin:
        hdl.modulelinuxattach(ns.module, ns.debug_plugin)
    elif not ns.module and ns.debug_plugin:
        hdl.linuxattach(ns.debug_plugin)
    elif  ns.module and not ns.debug_plugin:
        hdl.modulelinuxattach(ns.module)
    else:
        log.info('Invalid arguments- module or debug_plugin needed')
        print('Invalid arguments- module or debug_plugin needed')
        return

    ls_out=hdl.lexec('ls -1 /isan/etc/sysmgr.d')
    pattern='([a-zA-Z0-9\_\-]+\.conf)\s+'
    conf_files=re.findall( pattern, ls_out )

    for conf_file in conf_files:
        cmd='cat /isan/etc/sysmgr.d/{0}'.format(conf_file)
        cmd = cmd + ' | grep [a-zA-Z0-9\{\}]'
        file_content=hdl.lexec(cmd)
        single_sup_ha_flag=False
        dual_sup_ha_flag=False
        ha_policy1_flag=False
        ha_policy2_flag=False
       
        for line in file_content.split('\r\n'):
             if re.search( 'short_name', line, re.I ):
                 (short_name_label, short_name)=line.split('=')
                 match=re.search( '([a-zA-Z0-9\-\_]+)', short_name, re.I )
                 srv_name=match.group(1)
                 sysmgr_conf_dict[srv_name]={}

             if re.search( 'uuid', line, re.I ):
                 (uuid_label, uuid)=line.split('=')
                 sysmgr_conf_dict[srv_name]['uuid']=uuid

             if re.search( 'timeout', line, re.I ):
                 (timeout_label, heartbeat_timeout)=line.split('=')
                 sysmgr_conf_dict[srv_name]['heartbeat_timeout']=heartbeat_timeout

             if re.search( 'single_sup', line, re.I ):
                 single_sup_ha_flag=True

             if re.search( 'dual_sup', line, re.I ):
                 dual_sup_ha_flag=True

             if re.search( 'ha_policy', line, re.I ):
                 if ha_policy1_flag:
                     ha_policy2_flag=True
                     ha_policy1_flag=False
                 else:
                     ha_policy1_flag=True
                     ha_policy2_flag=False

             if re.search( 'restart', line, re.I ):
                 (restart_label, restart )=line.split('=')
                 if ha_policy1_flag:
                    sysmgr_conf_dict[srv_name]['ha_policy1_restart']=restart
                 if ha_policy2_flag:
                    sysmgr_conf_dict[srv_name]['ha_policy2_restart']=restart
               
             if re.search( 'maxretry', line, re.I ):
                 (retry_label, retry )=line.split('=')
                 if ha_policy1_flag:
                    sysmgr_conf_dict[srv_name]['ha_policy1_maxretry']=retry
                 if ha_policy2_flag:
                    sysmgr_conf_dict[srv_name]['ha_policy2_maxretry']=retry
               
             if re.search( ' heap ', line, re.I ):
                 match=re.search( '([0-9]+)', line, re.I )
                 sysmgr_conf_dict[srv_name]['heap_size']=match.group(1)

             if re.search( ' stack ', line, re.I ):
                 match=re.search( '([0-9]+)', line, re.I )
                 sysmgr_conf_dict[srv_name]['stack_size']=match.group(1)

             if re.search( ' log =', line, re.I ):
                 if re.search( '([0-9]+)', line, re.I ):
                     match=re.search( '([0-9]+)', line, re.I )
                     sysmgr_conf_dict[srv_name]['log_size']=match.group(1)

             if re.search( 'restart', line, re.I ):

                 if single_sup_ha_flag:
                    (single_label, single_sup_restart)=line.split('=')
                    sysmgr_conf_dict[srv_name]['single_sup_restart']=single_sup_restart 

                 if dual_sup_ha_flag:
                    (dual_label, dual_sup_restart)=line.split('=')
                    sysmgr_conf_dict[srv_name]['dual_sup_restart']=dual_sup_restart 
                 
             if re.search( '\}', line, re.I ):

                 if single_sup_ha_flag:
                     single_sup_ha_flag=False

                 if dual_sup_ha_flag:
                     dual_sup_ha_flag=False
                 
        if not sysmgr_conf_dict[srv_name].has_key('uuid'):
           sysmgr_conf_dict[srv_name]['uuid']=None

        if not sysmgr_conf_dict[srv_name].has_key('heartbeat_timeout'):
           sysmgr_conf_dict[srv_name]['heartbeat_timeout']=None
      
        if not sysmgr_conf_dict[srv_name].has_key('ha_policy1_restart'):
           sysmgr_conf_dict[srv_name]['ha_policy1_restart']=None
            
        if not sysmgr_conf_dict[srv_name].has_key('ha_policy2_restart'):
           sysmgr_conf_dict[srv_name]['ha_policy2_restart']=None

        if not sysmgr_conf_dict[srv_name].has_key('ha_policy1_maxretry'):
           sysmgr_conf_dict[srv_name]['ha_policy1_maxretry']=None

        if not sysmgr_conf_dict[srv_name].has_key('ha_policy2_maxretry'):
           sysmgr_conf_dict[srv_name]['ha_policy2_maxretry']=None

        if not sysmgr_conf_dict[srv_name].has_key('stack_size'):
           sysmgr_conf_dict[srv_name]['stack_size']=None

        if not sysmgr_conf_dict[srv_name].has_key('heap_size'):
           sysmgr_conf_dict[srv_name]['heap_size']=None
    
        if not sysmgr_conf_dict[srv_name].has_key('log_size'):
           sysmgr_conf_dict[srv_name]['log_size']=None


    #print '%20s\t\t%15s\t\t%15s\t\t%15s' % ( 'Service Name', 'Heap Size', 'Stack Size', 'Log Size' )
    for srv_name in sysmgr_conf_dict.keys():
        print('%20s\t\t%15s\t\t%15s\t\t%15s' % ( srv_name, sysmgr_conf_dict[srv_name]['heap_size'],                   \
               sysmgr_conf_dict[srv_name]['stack_size'], sysmgr_conf_dict[srv_name]['log_size'] ))
 
### Method to get all the IPv4 address given a prefix, step and count
def getIPv4AddressesList(prefix_start, step, count):
    retList=[]
    tmp=ipaddr.IPv4Network(prefix_start)
    prefix=tmp.network
    prefixlen=tmp.prefixlen
    #retList.append(str(prefix) + '/' + str(prefixlen))
    retList.append(str(prefix))
    for cnt in range(1, count):
        prefix=incrementIpv4Address(str(prefix), step)
        #retList.append(prefix + '/' + str(prefixlen))
        retList.append(prefix)
    return retList

def getMacAddressList(mac_addr_start,step,count):
    retList=[]
    retList.append(mac_addr_start)
    mac=mac_addr_start
    for cnt in range(1, count):
          mac=incrementMacAddress(mac,step)
          retList.append(mac)
    return retList

### Method to get all the IPv6 address given a prefix, step and count
def getIPv6AddressesList(prefix_start, step, count):
    retList=[]
    tmp=ipaddr.IPv6Network(prefix_start)
    prefix=tmp.network
    prefixlen=tmp.prefixlen
    retList.append(str(prefix) + '/' + str(prefixlen))
    for cnt in range(1, count):
        prefix=incrementIpv6Address(prefix, step)
        retList.append(str(prefix) + '/' + str(prefixlen))
    return retList




def getFpToBcmMapping( log, interface ):
  
    """ Function to derive the BCM port for a given front panel port on TEST LINE CARDS
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!! PLEASE NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!! THIS IS ONLY FOR TEST LC !!!!!!!!!!!!!!!!!!!!!!!!!!!
    """
 
    intf=normalizeInterfaceName(log,interface)

    match=re.search( 'Eth([0-9]+)\/([0-9]+)', intf, re.I )
    mod_no=int(match.group(1))
    port_no=int(match.group(2))

    if 1 <= port_no <= 20:
       bcm_no=1
    elif 21 <= port_no <= 34:
       bcm_no=0
    else:
       print('Incorrect port range given .. Valid port number is from 1 to 34')

    if bcm_no==0:
       if port_no == 21:
          bcm_port_no=0
       else:
          bcm_port_no = int(port_no) - 21

    if bcm_no==1:
       if port_no == 1:
          bcm_port_no=0
       else:
          bcm_port_no = int(port_no) - 1

    bcm_port_val='{0}/{1}/xe{2}'.format( mod_no, bcm_no, bcm_port_no )
    msg='Front Panel port = {0}, module/unit/port = {1}'.format( intf, bcm_port_val )
    print(msg)
    log.info(msg)
    return bcm_port_val


def getBcmToFpMapping( log, bcm_port_val ):

    """ Function to derive the Front Panel Port for a given BCM port on TEST LINE CARDS
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!! PLEASE NOTE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!! THIS IS ONLY FOR TEST LC !!!!!!!!!!!!!!!!!!!!!!!!!!!
    """
    (mod_no,bcm_no,bcm_port_numb)=bcm_port_val.split('/')
    match=re.search( 'xe([0-9]+)', bcm_port_numb, re.I )
    bcm_port_no=int(match.group(1))

    if int(bcm_no) == 1:
       fp_port_no = bcm_port_no + 1
    elif int(bcm_no) == 0:
       fp_port_no = bcm_port_no + 21
    else:
       print('Incorrect bcm_port_no seen. Valid values are in the range 0 to 19')
   
    fp_port = 'Eth{0}/{1}'.format(mod_no, fp_port_no)

    msg='BCM interface {0} maps to Front Panel Port {1}'.format( bcm_port_val, fp_port )
    print(msg)
    log.info(msg)
    return fp_port 

### added by swanaray
def getIpAdjacencyDict(hdl, log, module, *args):
    arggrammar={}
    arggrammar['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if not ns.VALIDARGS:
        log.warning('Invalid arguments')
        return []

    
    # Returns dict of "show forwarding adjacency'
    if ns.vrf:
        output=hdl.execute('show forwarding vrf {0} adjacency module {1}'.format(ns.vrf, module))
    else:
        output=hdl.execute('show forwarding adjacency module {0}'.format(module))

    pattern="("+rex.IPv4_ADDR+")"
    pattern=pattern+"[ \t]+("+rex.MACADDR+")"
    pattern=pattern+"[ \t]+("+rex.INTERFACE_NAME+")"
    adj_list = re.findall(pattern,output)
    log.info("IPv4 Adjacency List: " + str(adj_list))
    adj_dict = convertListToDict(adj_list,['Address','MAC_Address','Interface'],['Address'])
    log.info("IPv4 Adjacency Dict: " + str(adj_dict))
    return adj_dict

### added by swanaray
def getIPv6AdjacencyDict(hdl, log, module, *args):
    arggrammar={}
    arggrammar['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if not ns.VALIDARGS:
        log.warning('Invalid arguments')
        return []


    # Returns dict of "show forwarding adjacency'
    if ns.vrf:
        output=hdl.execute('show forwarding vrf {0} ipv6 adjacency module {1}'.format(ns.vrf, module))
    else:
        output=hdl.execute('show forwarding ipv6 adjacency module {0}'.format(module))

    pattern="("+rex.IPv6_ADDR+")"
    pattern=pattern+"[ \t]+("+rex.MACADDR+")"
    pattern=pattern+"[ \t]+("+rex.INTERFACE_NAME+")"
    adj_list = re.findall(pattern,output)

    ### convert IPv6 address to standard (exploded format)
    for i in range(len(adj_list)):
        tmp=list(adj_list[i])
        tmp[0]=ipaddr.IPv6Address(tmp[0]).exploded
        adj_list[i]=tuple(tmp)

    log.info("IPv6 Adjacency List: " + str(adj_list))
    adj_dict = convertListToDict(adj_list,['Address','MAC_Address','Interface'],['Address'])
    log.info("IPv6 Adjacency Dict: " + str(adj_dict))
    return adj_dict

def getIPv6FwdRouteModuleDict(hdl,log,*args):
    #Returns the dictionary of forwarding route table on a module
    arggrammer={}
    arggrammer['module']='-type str -required True'
    arggrammer['vrf']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
    msg='Fetch IPv6 forwarding route table on module {0} on {0}'.format(ns.module, hdl.switchName)
    log.info(msg)
    sw_cmd='show forwarding ipv6 route module {0}'.format(ns.module)
    if ns.vrf:
        sw_cmd+=' vrf '+ns.vrf
    output=hdl.execute(sw_cmd)
    route_dict={}
    eol='[\r\n\t ]+'
    sub_pattern='[ \t]*?([a-zA-Z0-9\.\:]+).[ \t]+({0})'.format(rex.INTERFACE_NAME)
    pattern='({0})\/([0-9]+)[ \t]*?((?:{1}{2})+)'.format(rex.IP_ADDRESS,eol,sub_pattern)
    capture_pattern='([a-zA-Z0-9\.\:]+).[ \t]+({0})'.format(rex.INTERFACE_NAME)
    match=re.findall(pattern,output,re.I|re.DOTALL)
    if len(match):
       for route in match:
           tmp=list(route)
           tmp[0]=ipaddr.IPv6Address(tmp[0]).exploded
           route=tuple(tmp)
           sub_match=re.findall(capture_pattern,route[2],re.I|re.DOTALL)
           next_hop={}
           for nh in sub_match:
               if re.search(rex.IP_ADDRESS, str(nh)):
                   tmp=list(nh)
                   tmp[0]=ipaddr.IPv6Address(tmp[0]).exploded
                   nh=tuple(tmp)
               next_hop[nh[0]]={}
               next_hop[nh[0]]['interface']=nh[1].strip().strip(',')
           tmp={}
           tmp[route[0], route[1]]={'nexthop':next_hop}
           route_dict.update(tmp)
    return route_dict

def getLinuxIpMacAddress(interface, log, *args):
    arggrammar={}
    arggrammar['ipv4']='-type bool'
    arggrammar['ipv6']='-type bool'
    arggrammar['oneMandatory']=[('ipv4','ipv6')]
    ns=parserutils_lib.argsToCommandOptions(args, arggrammar, log)
    if not ns.VALIDARGS:
        log.error('fail','getLinuxIpMacAddress has invalid ' + \
            'parameters {0}'.format(args))
        return {}
    proc = subprocess.Popen(["ifconfig {0}".format(interface)], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    ### get the mac address
    m=re.search('HWaddr +({0})'.format(rex.MACADDR),out,re.I)
    if m:
        mac=sanitizeMac(m.group(1))
    else:
        return {}
    if ns.ipv4:
        m=re.search('inet addr:({0})'.format(rex.IPv4_ADDR), out, re.I)
        if m:
            return (mac + ', ' + m.group(1))
        else:
            return {}
        

def getSupSlots (hdl,log,*args):
    """Author: anandksi
    Returns list of Sup slots on the switch
    """                                                                                      
    cmd_out = hdl.execute("show module | grep -i sup")
    pattern = '({0})\s+{0}\s+{1}\s+{1}\s+{1}'.format(rex.NUM,rex.ALPHANUMSPECIAL)
    return re.findall(pattern, cmd_out)



def getRouterMac( hdl, log ):
    """
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    Note - Using show vdc for now. Will be changed later if this is not supported but use
    this function to fetch Router Mac so that the changes are contained to one function
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    Usage: 
    getRouterMac( hdl, log ) 
    """

    pattern='1\s+{0}\s+{1}\s+({2})\s+{1}\s+'.format( rex.SWITCH_NAME, rex.ALPHANUM, rex.MACADDR )
    show_out=hdl.execute('show vdc')
    if re.search( pattern, show_out, re.I ):
        match=re.search( pattern, show_out, re.I )
        router_mac=match.group(1)
        return router_mac
    else:
        log.error('ERROR !! Fetching the Router MAC from the switch')
        return -1



def getSviDict( hdl, log, *args ):

    """
    Function to return the output of one or more SVI interfaces given as a list

    Usage:
    getSviDict( hdl, log )
    getSviDict( hdl, log, '-svi_list Vlan2-10,Vlan21' )

    Sample Output: Collected for vlan2

    OrderedDict([('2', OrderedDict([('State', 'up'), ('Line_protocol_state', 'up'), ('Hardware', 'EtherSVI'), ('Mac_address', '0022.bdf3.7b81'), ('Ip_address', '1.2.1.3'), ('Ip_prefix_len', '16'), ('MTU', '1500'), ('BW', '1000000'), ('DLY', '10'), ('reliability', '255'), ('txload', '1'), ('rxload', '1'), ('Encapsulation', 'ARPA'), ('input_rate_interval', '60'), ('input_rate_bps', '0'), ('input_rate_pps', '0'), ('Load_interval_key', '60'), ('Load_interval', '0'), ('Load_interval_secs', '0'), ('L3_switched_input_pkts', '2'), ('L3_switched_input_bytes', '5'), ('L3_switched_output_pkts', '300'), ('L3_switched_output_bytes', '0'), ('L3_in_switched_ucast_pkts', '0'), ('L3_in_switched_ucast_bytes', '0'), ('L3_in_switched_mcast_pkts', '0'), ('L3_in_switched_mcast_bytes', '0'), ('L3_out_switched_ucast_pkts', '0'), ('L3_out_switched_ucast_bytes', '0'), ('L3_out_switched_mcast_pkts', '0'), ('L3_out_switched_mcast_bytes', '0')]))]) 
    
    """
    arggrammar={}
    arggrammar['svi_list']='-type str'
    ns=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

    pattern='Vlan({0})\s+is\s+({1}).*,\s+line protocol is\s+({1})\r\n\s+Hardware is ({1}), address is\s+({2})\r\n\s+Internet Address is\s+({3})\/({0})\r\n\s+MTU\s+({0})\s+bytes,\s+BW\s+({0})\s+[a-zA-z]+,\s+DLY\s+({0})\s+[a-zA-z]+,\r\r\n\s+reliability\s+({0})\/{0},\s+txload\s+({0})\/{0},\s+rxload\s+({0})\/{0}\r\n\s+Encapsulation\s+({1}),\s+[a-zA-z ]+\r\n\s+[a-zA-z \:\"]+\r\n\s+[a-zA-z \:\"]+\r\n\s+[a-zA-z \:\"]+\r\n\s*({0})\s+seconds\s+input\s+rate\s+({0})\s+bits\/sec,\s+({0})\s+packets\/sec\r\n\s*\s*({0})\s+seconds\s+output\s+rate\s+({0})\s+bits\/sec,\s+({0})\s+packets\/sec\r\n\s+Load-Interval\s+#({0}):\s+({0})\s+[a-zA-z]+\s+\(({0})\s+[a-zA-z]+\)\r\n\s+input rate ({0}) bps, ({0}) pps;\s+output rate\s+({0})\s+bps,\s+({0})\s+pps\r\n\s+L3 Switched:\r\n\s+input:\s+({0})\s+pkts,\s+({0})\s+bytes\s+\-\s+output:\s+({0})\s+pkts,\s+({0})\s+bytes\r\n\s+L3 in Switched:\r\n\s+ucast:\s+({0})\s+pkts,\s+({0})\s+bytes\s+\-\s+mcast:\s+({0})\s+pkts,\s+({0})\s+bytes\r\n\s+L3 out Switched:\r\n\s+ucast:\s+({0})\s+pkts,\s+({0})\s+bytes\s+\-\s+mcast:\s+({0})\s+pkts,\s+({0})\s+bytes'.format( rex.NUM, rex.ALPHANUM, rex.MACADDR, rex.IPv4_ADDR )
 
    if ns.svi_list is not None:
        svi_list=ns.svi_list
        cmd='show interface {0}'.format(svi_list)
    else:
        cmd='show interface'


    show_svi=hdl.execute(cmd)
    list_svi=re.findall( pattern, show_svi, re.I )
    svi_dict=convertListToDict( list_svi, ['Vlan_id', 'State', 'Line_protocol_state', 'Hardware', 'Mac_address', 'Ip_address',     \
       'Ip_prefix_len', 'MTU', 'BW', 'DLY', 'reliability', 'txload', 'rxload', 'Encapsulation', 'input_rate_interval',             \
       'input_rate_bps', 'input_rate_pps', 'Load_interval_key', 'Load_interval', 'Load_interval_secs', 'L3_switched_input_pkts',   \
       'L3_switched_input_bytes', 'L3_switched_output_pkts', 'L3_switched_output_bytes', 'L3_in_switched_ucast_pkts',              \
       'L3_in_switched_ucast_bytes', 'L3_in_switched_mcast_pkts', 'L3_in_switched_mcast_bytes', 'L3_out_switched_ucast_pkts',      \
       'L3_out_switched_ucast_bytes', 'L3_out_switched_mcast_pkts', 'L3_out_switched_mcast_bytes' ], [ 'Vlan_id' ] )

    log.debug('%%% svi_dict %%% {0}'.format( svi_dict ))

    return svi_dict  


#######


def getSviRouterMacDict( hdl, log ):

    """

    Get a dict of Vlan ID to Router Mac mapping From SVI dict
    Usage:
    getSviRouterMacDict( hdl, log )

    """

    svi_rmac_dict={}

    svi_dict=getSviDict( hdl, log )

    for vlan_id in svi_dict.keys():
         svi_rmac_dict[vlan_id]=svi_dict[vlan_id]['Mac_address'] 

    log.debug( '%%% svi_rmac_dict %%% {0}'.format(svi_rmac_dict))

    return svi_rmac_dict 


########


def getUniqueRouterMacAddrDict( hdl, log ):

    """
    Get the unique list of Router MACs on the Agg/EOR box. This should fetch one entry for the Router MAC and
    fetch all the HSRP/VRRP MACs, user configured MAC address for L3.

    The Key for the dict is Rmac and if needed you can fetch the Vlanid for the RMAC. Please note, the vlan-id
    will be "-" for GMAC.
 
    Usage:
    getUniqueRouterMacAddrDict( hdl, log )

    """
    pattern='\s+([0-9\-]+)\s+({0})\s+static'.format(rex.MACADDR)
    show_mac=hdl.execute( 'show mac address-table static | inc sup-eth1')
    mac_list=re.findall( pattern, show_mac, re.I )
    mac_dict=convertListToDict( mac_list, ['Vlan_id', 'Rmac' ], ['Rmac'] )
    return mac_dict

########


def getShowSnmpTrapDict( hdl, log ):

    show_snmp=hdl.execute('show snmp trap')
    pattern='([a-zA-Z0-9\-\_]+)\s+\:\s+([a-zA-Z0-9\-\_]+)\s+([a-zA-Z]+)'
    snmp_trap_dict={}
    match_list=re.findall( pattern, show_snmp, re.I )
    snmp_trap_dict=convertListToDict( match_list, [ 'Trap type', 'Description', 'Enabled' ], ['Trap type' ] )
    return snmp_trap_dict

def getIntfQueuingPFCStatsDict(hdl,log,*args):
    """ 
    Added by sandesub
    Returns the per COS QOS group TXPPP and RXPPP stats
    """
    arggrammar={}
    arggrammar['intf']='-type str -required True'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    output = hdl.execute('show queuing interface {0} | begin "PFC"'.format(ns.intf))
    pattern="("+rex.NUM+")"
    pattern=pattern+"[ \t]+("+rex.ALPHANUMSPECIAL+")"
    pattern=pattern+"[ \t]+("+rex.ALPHA+")"
    pattern=pattern+"[ \t]+("+rex.NUM+")"
    pattern=pattern+"[ \t]+("+rex.ALPHA+")"
    pattern=pattern+"[ \t]+("+rex.NUM+")"
    cos_pfc_count_list=re.findall(pattern,output,flags=re.M)
    cos_pfc_count_dict=convertListToDict(cos_pfc_count_list,['COS','QOS_Group','TxPause','TxCount','RxPause','RxCount'],['COS'])
    return cos_pfc_count_dict
     
def getIntfQueuingQoSGroupStatsDict(hdl,log,*args):
    """ 
    Added by sandesub
    Returns the per QOS group TX pkts and per QOS group Dropped pkts with the following as keys:
    1. qos_group as the top-level key 
    2. 'TX' and 'Dropped' as 2nd level keys
    3. 'Unicast', 'OOBFC_Unicast' and 'Multicast' as 3rd level keys
    """
    arggrammar={}
    arggrammar['intf']='-type str -required True'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log,'namespace')
    final_tx_dict = {}
    temp_dict = {}
    for qos_group in range (0,4):
        qos_str = str(qos_group)
        output = hdl.execute('show queuing interface {0} | grep -A 8 "QOS GROUP {1}" | grep "Pkts"'.format(ns.intf,qos_group))
        pattern="\|[ \t]+("+rex.ALPHA+")[ \t]+Pkts[ \t]+\|[ \t]+("+rex.NUM+")\|[ \t]+("+rex.NUM+")\|[ \t]+("+rex.NUM+")\|"
        tx_pkt_list=re.findall(pattern,output,flags=re.M)
        #print tx_pkt_list
        #item = tx_pkt_list[0]
        #t = ()
        #t = t + (qos_str,)
        #t = t + item
        #tx = []
        #tx.append(t)
        tx_dict=convertListToDict(tx_pkt_list,['Pkts','Unicast','OOBFC_Unicast','Multicast'],['Pkts'])
        #print tx_dict
        temp_dict = {qos_str:tx_dict}
        final_tx_dict.update(temp_dict)
    #print final_tx_dict    
    return final_tx_dict


######

def collectInbandPathStats(hdl, interfaces, log):
    """
    params:
       hdl: 
       interfaces: string, for example: eth3/1,eth3/3-5,Eth2/1,Ethernet8/1,ethernet8/2-5
       log:
 
    """
    base_date_string = str(re.sub('\s', '_', time.asctime()))
    filename = '/tmp/{0}_{1}.log'.format('collectInbandPathStats', base_date_string)
    flog = getLog(filename)

    intf_dict = getIntfDict(hdl, interfaces, log)

    for intf in intf_dict.keys():
       
       lc_mod = intf_dict[intf]['lc_mod']
       lc_ins = intf_dict[intf]['lc_ins']
       lc_port = intf_dict[intf]['lc_port']

       # 1. Front panel Port Stats
  
       flog.info('===========================================================')
       flog.info('========= 1. Collecting front panel port stats   ==========')
       flog.info('=========    Interface: {0}         =========='.format(intf))
       flog.info('===========================================================')

       # a.
       cmds = ['show hardware internal interface {0} asic counters'.format(intf),
              ]
       pkt_drop_pats = ['RFLDR[ \t]+([0-9]+)',
                        'RDBGC0[ \t]+([0-9]+)',
                        'RDBGC6[ \t]+([0-9]+)',
                        'DROP_PKT_ING[ \t]+([0-9]+)',
                        'UCQ_DROP_PKT[ \t]+([0-9]+)',
                       ]
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

       # b. Ingress per port per PG instant buffer stats
       cmds = [
               'show hardware internal buffer info pkt-stats input module {0} instance {1}'.format(lc_mod, lc_ins),
               'show policy-map interface {0} type qos'.format(intf),
              ]
       pkt_drop_pats = ['queue dropped pkts : ([0-9]+)',
                       ]
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

       # c. egress per port per CosQ instant buffer stats
       cmds = [
               'show hardware internal buffer info pkt-stats module {0} instance {1} detail'.format(lc_mod, lc_ins),
               'show policy-map interface {0} type queuing'.format(intf),
              ]
       pkt_drop_pats = ['queue dropped pkts : ([0-9]+)',
                       ]
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)
      
       # 2. Traffic between ASIC and CMIC ON LC
       flog.info('=================================================================')
       flog.info('======  2. Collecting stats between ASIC and CMIC ON LC   =======')
       flog.info('=================================================================')

       # a/b/c/d
       cmds = [
               'show hardware internal CPU interface asic counters module {0} instance {1}\
               '.format(lc_mod, lc_ins),
               #'show hardware internal access-list sup-tcam',
               'show policy-map interface control-plane',
               'show hardware internal buffer info pkt-stats cpu',
              ]
       pkt_drop_pats = ['dropped ([0-9]+) packets',
                        'DROP_PKT\([0-9]+\)[ \t]+([0-9]+)',
                        'DROP_PKT_ING\.hg[0-9]+[ \t]+:[ \t]+[[0-9]+,]*[0-9]+',
                       ]
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)
 
       cmds = [
               'bcm-shell module {0} \"{1}: show c cpu\"'.format(lc_mod, lc_ins),
               'bcm-shell module {0} \"{1}: show c hg\"'.format(lc_mod, lc_ins),
              ]
       pkt_drop_pats = ['DROP',
                       ]
       searchInOutput(hdl, flog, cmds, pkt_drop_pats)

       # 3. Determine HG port on FM that sup traffic is sent to
       flog.info('===========================================================')
       flog.info('======  3. Collecting HG port stats on LC and FM    =======')
       flog.info('===========================================================')

       # get FM module according to "show policy-map interface control-plane" output
       fm_mod = getFM(hdl)
       flog.info('FM {0} is used for lc {1} unit {2} to transmit the packets to CPU\
                 '.format(fm_mod, lc_mod, lc_ins))

       # get HiGig port on FM 
       fm_dict = getHG(hdl, fm_mod, lc_mod, lc_ins)
       if fm_dict:
          flog.info('On FM {0} HG{1} on unit {2} is used to transmit the packets to CPU\
                    '.format(fm_mod, fm_dict['fm_hg']-1, fm_dict['fm_ins']))
        
          cmds = [
                  'show system internal fabric connectivity module {0}'.format(fm_mod),
                  'show hardware internal cpu-mac inband active-fm traffic-from-sup',
                  'show hardware internal fabric interface asic counters module {0} instance {1} asic-port {2}\
                  '.format(lc_mod, lc_ins, fm_dict['lc_hg']),
                  'slot {0} quoted \"show hardware internal interface indiscard-stats instance {1} asic-port {2}\"\
                  '.format(lc_mod, lc_ins, fm_dict['lc_hg']),
                  'show hardware internal fabric interface asic counters module {0} instance {1} asic-port {2}\
                  '.format(fm_mod, fm_dict['fm_ins'], fm_dict['fm_hg']),
                  'slot {0} quoted \"show hardware internal interface indiscard-stats instance {1} asic-port {2}\"\
                  '.format(fm_mod, fm_dict['fm_ins'], fm_dict['fm_hg']),
                 ] 
          pkt_drop_pats = ['RFLDR[ \t]+([0-9]+)',
                           'RDBGC0[ \t]+([0-9]+)',
                           'RDBGC6[ \t]+([0-9]+)',
                           'DROP_PKT_ING[ \t]+([0-9]+)',
                           'UCQ_DROP_PKT[ \t]+([0-9]+)',
                           '\S+ Discards[ \t]+([0-9]+)',
                           '\S+ Drops[ \t]+([0-9]+)',
                          ]
          searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

          cmds = [
                  'bcm-shell module {0} \"{1}: show c cpu\"'.format(fm_mod, fm_dict['fm_ins']),
                  'bcm-shell module {0} \"{1}: show c hg\"'.format(fm_mod, fm_dict['fm_ins']),
                 ]
          pkt_drop_pats = ['DROP',
                          ]
          searchInOutput(hdl, flog, cmds, pkt_drop_pats)
           

       else: 
          flog.info('SKIP step 3: Not find coresponding HiGig port on FM {0}'.format(fm_mod))
          flog.error('SKIP step 3: Not find coresponding HiGig port on FM {0}'.format(fm_mod))

       # 4. Traffic between ASIC and CMIC ON FM
       flog.info('================================================================')
       flog.info('====== 4. Collecting stats between ASIC and CMIC ON FM   =======')
       flog.info('================================================================')

       # a. CMIC port stats
       if fm_dict:
         cmds = [
                 'show hardware internal CPU interface asic counters module {0} instance {1}\
                 '.format(fm_mod, fm_dict['fm_ins']),
                ]
         pkt_drop_pats = ['dropped ([0-9]+) packets',
                          'DROP_PKT\([0-9]+\)[ \t]+([0-9]+)',
                          'DROP_PKT_ING\.hg[0-9]+[ \t]+:[ \t]+[[0-9]+,]*[0-9]+',
                         ]
         searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)
       else: 
          flog.info('SKIP step 4: Not find coresponding HiGig port on FM {0}'.format(fm_mod))
          flog.error('SKIP step 4: Not find coresponding HiGig port on FM {0}'.format(fm_mod))

       # 5. CMIC <-> CPU Stats ON FM
       flog.info('================================================================')
       flog.info('======  5. Collecting CMIC <-> CPU stats on FM   =======')
       flog.info('================================================================')
       pkt_drop_pats = ['errors:([0-9]+)',
                        'dropped:([0-9]+)',
                        'overruns:([0-9]+)',
                        'collisions:([0-9]+)',
                       ] 
       success = 0
       output = hdl.execute('dir |  grep plug')
       pattern = r':[0-9]+[ \t]+[0-9]+[ \t]+([-\.\w]+)\r$'
       dplugs = re.findall(pattern, output, re.M)
       hdl.execute('attach module {0}'.format(fm_mod))
       for each in dplugs:
         output = hdl.execute('load bootflash:{0}'.format(each))
         pattern = r'Successfully loaded bash debug-plugin!!!'
         match = re.search(pattern, output)
         if not match:
           continue
         else:
           success = 1
           break

       if success:
         cmds = ['ifconfig knet0_0',
                 'ifconfig knet0_1',
                 'ifconfig inband',
                ]
         for cmd in cmds:
            flog.info(cmd)
            output = hdl.execute(cmd)
            flog.info(output)
            for line in output.split('\n'):
               for pat in pkt_drop_pats:
                  match = re.search(pat, line)
                  if match:
                     if match.group(1) != '0':
                        flog.error('\"{0}\" on FM {1} CPU: {2}'.format(cmd, fm_mod, line))
                        continue
         hdl.execute('exit')
         hdl.execute('exit')
       else:
         #print 'Please load debug_plugin!!!!'
         hdl.execute('exit')

       # 6. FM: Traffic between CPU and Inband Switch on FM
       flog.info('================================================================')
       flog.info('======  6. Traffic between CPU and inband Switch on FM   =======')
       flog.info('================================================================')
       cmds = [
               'slot {0} quoted \"show mvdxn internal port-status\"'.format(fm_mod),
               'slot {0} quoted \"show mvdxn internal port-stats\"'.format(fm_mod),
              ]
       pkt_drop_pats = []
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

       # 7. FM: InBand switch on FM to Marvel EPC switch on SC
       flog.info('================================================================')
       flog.info('======  7. FM: Inband switch on FM to Marvel EPC switch on SC ==')
       flog.info('======  Same as above                                         ==')
       flog.info('================================================================')

       # 8. SC: Marvel EPC Switch on SC <-> Sup Ethernet Port
       flog.info('================================================================')
       flog.info('======  8. SC: Marvel EPC switch on SC <-> SUP Ethernet Port ===')
       flog.info('================================================================')
       sc_mod = getSC(hdl)
       if sc_mod != 0:
          cmds = [
                  'slot {0} quoted \"show mvdxn internal port-status\"'.format(sc_mod),
                  'slot {0} quoted \"show mvdxn internal port-stats\"'.format(sc_mod),
                 ]
          pkt_drop_pats = []
          searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

       # 9. Sup NIC Stats:
       flog.info('================================================================')
       flog.info('====== 9. Sup NIC stats                                 =======')
       flog.info('================================================================')
       cmds = ['show hardware internal cpu-mac inband counters',
               'show hardware internal cpu-mac inband stats',
              ]
       pkt_drop_pats = ['errors:([0-9]+)',
                        'errors: ([0-9]+)',
                        'err: ([0-9]+)',
                        'failed: ([0-9]+)',
                        'dropped:([0-9]+)',
                        'drops: ([0-9]+)',
                        'overruns:([0-9]+)',
                        'collisions:([0-9]+)',
                        'collisions: ([0-9]+)',
                       ] 
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

       # 10. Netstats Stats
       flog.info('================================================================')
       flog.info('====== 10. Collecting netstack stats                     =======')
       flog.info('================================================================')
       cmds = ['show system internal pktmgr stats',
              ]
       pkt_drop_pats = ['.*err ([0-9]+)',
                        '.*drop ([0-9]+)',
                        '.*fail ([0-9]+)',
                       ]
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

       # 11. Inband Queuing Stats
       flog.info('=================================================================')
       flog.info('====== 11. Collecting Inband Queuing stats                =======')
       flog.info('=================================================================')
       cmds = ['show system inband queuing statistics',
              ]
       pkt_drop_pats = ['bpdu: recv [0-9]+, drop ([0-9]+)',
                        '\(q0\): recv [0-9]+, drop ([0-9]+)',
                       ]
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

       # 13. show tech-support to pull all forward/drops/error counters 
       #    from all linecards/instances/ports/interfaces/reasons to ease debugging
       flog.info('===============================================================')
       flog.info('====== 13. Collecting show tech-support inband counters =======')
       flog.info('===============================================================')
       cmd = 'show tech-support inband counters'
       flog.info(cmd)
       #flog(hdl.execute(cmd))

    return filename
  
def collectNetstackStats(hdl, interfaces, log):
    """
    params:
       hdl: 
       interfaces: string, for example: eth3/1,eth3/3-5,Eth2/1,Ethernet8/1,ethernet8/2-5
       log:
 
    """
    base_date_string = str(re.sub('\s', '_', time.asctime()))
    filename = '/tmp/{0}_{1}.log'.format('collectNetstackStats', base_date_string)
    flog = getLog(filename)

    intf_dict = getIntfDict(hdl, interfaces, log)

    for intf in intf_dict.keys():
       lc_mod = intf_dict[intf]['lc_mod']
       lc_ins = intf_dict[intf]['lc_ins']

       # 1. Packet Manager
       flog.info('===========================================================')
       flog.info('========    Collecting stats from packet Manager   ========')
       flog.info('===========================================================')
       cmds = ['show system internal pktmgr interface {0}'.format(intf),
               'show system internal pktmgr client',
               'show system internal pktmgr interface vdc inband',
               'show system internal pktmgr interface vdc mgmt',
               'show system internal pktmgr interface vdc mgmt-vdc',
               'show system internal pktmgr stats',
               'show system internal pktmgr stats brief',
              ]

       pkt_drop_pats = ['Total Rx: [0-9]+, Drop: ([0-9]+), Tx: [0-9]+, Drop: ([0-9])+',
                         '[0-9]+[ \t]+0x\w+[ \t]+[a-zA-Z]+[ \t]+([0-9]+)',
                         '[ \t]*[a-z_]+.*_err ([0-9]+)',
                         'Inband kernel recv [0-9]+, drop ([0-9]+), rcvbuf [0-9]+, sndbuf [0-9]+', 
                         'Mgmt kernel recv [0-9]+, drop ([0-9]+), rcvbuf [0-9]+, sndbuf [0-9]+',
                        ]
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

       # 2. Ip
       flog.info('===============================================')
       flog.info('========    Collecting stats from IP   ========')
       flog.info('===============================================')
       cmds = ['show ip client',
               #'show ip route',
               'show ip traffic',
               'show ip interface {0}'.format(intf),
               'show ip process',
              ]

       pkt_drop_pats = ['Data messages, send successful: [0-9]+, failed: ([0-9]+)', 
                         'fail: ([0-9]+)',
                         'error[|s]: ([0-9]+)',
                         'drop[|s|ped]: ([0-9]+)',
                        ]
       searchDropInOutput(hdl, flog, cmds, pkt_drop_pats)

    return filename

def searchInOutput(hdl, flog, cmds, pkt_drop_pats):
    for cmd in cmds:
       output = hdl.execute(cmd)
       flog.info(cmd)
       flog.info(output)

       if not output:
         continue
  
       for line in output.split('\n'):
          for pat in pkt_drop_pats:
             match = re.search(pat, line)
             if match:
                flog.error('\"{0}\": {1}'.format(cmd, line))

def searchDropInOutput(hdl, flog, cmds, pkt_drop_pats):
    for cmd in cmds:
       output = hdl.execute(cmd)
       flog.info(cmd)
       flog.info(output)

       copp_flag = 0
       class_map = ''
       module = ''
       if cmd == 'show policy-map interface control-plane':
          copp_flag = 1 

       if not output:
         continue
  
       for line in output.split('\n'):
          if copp_flag:
             match = re.search(r'class-map (\S+) \(match-any\)', line)
             if match:
                class_map = match.group(1)
                continue
             match = re.search(r'(module [0-9]+)', line)
             if match:
                module = match.group(1)
                continue

          for pat in pkt_drop_pats:
             match = re.search(pat, line)
             if match:
                drop = match.group(1)
                if drop != '0':
                   if copp_flag:
                      flog.error('\"{0}\": class-map ({1}/{2}): {3}'.format(cmd, class_map, module, line))
                   else:
                      flog.error('\"{0}\": {1}'.format(cmd, line))
                   continue
 
def getSC(hdl):
    module = 0
    cmd = 'show module'
    output = hdl.execute(cmd)      
    for line in output.split('\n'):
       match = re.search(r'([0-9]+)   0      System Controller.*active', line)
       if match:
          module = int(match.group(1))
    return module

def getSCCardDict(hdl,log):

    cmd = 'show module'
    output = hdl.execute(cmd)      
    modules=re.findall('([0-9]+)\s+0\s+System Controller\s+([0-9A-Za-z\-]+)\s+([\S]+)', output)

    returndict={}
    for module in modules:
        returndict[module[0]]={}
        if module[2].strip() == '':
           returndict[module[0]]['model']=''
           returndict[module[0]]['Status']=module[1]
        else:
           returndict[module[0]]['model']=module[1]
           returndict[module[0]]['Status']=module[2]

    return returndict

def getSupCardDict(hdl,log):

    cmd = 'show module'
    output = hdl.execute(cmd)
    modules=re.findall('([0-9]+)\s+0\s+Supervisor Module\s+([0-9A-Za-z\-]+)\s+([\S]+)', output)

    returndict={}
    for module in modules:
        returndict[module[0]]={}
        if module[2].strip() == '':
           returndict[module[0]]['model']=''
           returndict[module[0]]['Status']=module[1]
        else:
           returndict[module[0]]['model']=module[1]
           returndict[module[0]]['Status']=module[2]

    return returndict

   
def getFM(hdl):
    module = 0
    cmd = 'show policy-map interface control-plane'
    output = hdl.execute(cmd)      
    for line in output.split('\n'):
       match = re.search(r'module ([0-9]+) :', line)
       if match:
          mod = int(match.group(1))
          if mod > 20 and mod < 27:
             module = mod
          continue
       if module < 20:
          continue
       match = re.search(r'transmitted ([0-9]+) packets;', line)
       if match:
          transmitted = int(match.group(1))
          if transmitted > 0:
             return module
    return module

def getHG(hdl, fm_mod, lc_mod, lc_ins):
    cmd = 'show system internal fabric connectivity module {0}'.format(fm_mod)
    pat = '{0}[ \t]+([0-9]+)[ \t]+HG([0-9]+)[ \t]+{1}[ \t]+{2}[ \t]+HG([0-9]+)'.format(fm_mod, lc_mod, lc_ins)
 
    output = hdl.execute(cmd)
    fm = []
    fm_found = {}
    for line in output.split('\n'):
       match = re.search(pat, line)
       if match:
          fm_dict = {}
          fm_dict['fm_ins'] = match.group(1)
          fm_dict['fm_hg'] = int(match.group(2)) + 1
          fm_dict['lc_hg'] = int(match.group(3)) + 1
          fm.append(fm_dict)
 
    for item in fm:
       cmd = 'show hardware internal fabric interface asic counters module {0} instance {1} \
              asic-port {2} | grep \"\(8\)\"'.format(fm_mod, item['fm_ins'], item['fm_hg'])
       pat = 'UC_PERQ_PKT\(8\)[ \t]+([0-9]+)'
 
       output = hdl.execute(cmd)
       match = re.search(pat, output)
       if match:
          fm_found = item
    return fm_found
  
def getLog(filename):
    log = logging.getLogger()
    hdlr = logging.FileHandler(filename)
    log.addHandler(hdlr)
    formatter = logging.Formatter('%(asctime)s - PYLOG - %(levelname)s - %(message)s')
    hdlr.setFormatter(formatter)
    log.setLevel(logging.INFO)
    
    return log

def getIntfDict(hdl, interfaces, log):
    intf_list = []
    intfs = interfaces.split(',')

    #normalize the interface name to "Eth3/1,Eth3/3-5,Eth2/1,Eth8/1,Eth8/2-5"
    for intf in intfs:
       interface = normalizeInterfaceName(log, intf)
       intf_list.append(interface)

    intf_single_list = getIntfSingleList(intf_list, log)
    intf_dict = getIntfDictFromList(hdl, intf_single_list, log)

    return intf_dict

def getIntfSingleList(intf_list, log):
    intf_single_list = []

    pattern_single = r'Eth([0-9]+)\/([0-9]+)$'
    pattern_range = r'Eth([0-9]+)\/([0-9]+)-([0-9]+)'

    for intf in intf_list:
       match = re.search(pattern_single, intf)
       if match:
          intf_single_list.append(intf)
          continue
     
       match = re.search(pattern_range, intf)
       if match:
          for i in range(int(match.group(2)), int(match.group(3))+1):
             intf_single_list.append('Eth{0}/{1}'.format(match.group(1), i))
          continue
       log.error('interface {0} is not valid, skipped'.format(intf))

    return intf_single_list

def getIntfDictFromList(hdl, intf_single_list, log):
    """
    params:
      hdl:
      intf_single_list: ['Eth8/1','Eth8/2','Eth8/3','Eth8/25']
    return: 
      intf_dict: {'Eth8/1':
                    'lc_mod': 8
                    'lc_ins': 1
                    'lc_port': 1
                  'Eth8/25':
                    'lc_mod': 8
                    'lc_ins': 0
                    'lc_port': 25
                  ...
                 }
    """
    intf_dict = {}
    pattern = r'Eth([0-9]+)\/([0-9]+)$'

    for intf in intf_single_list:
       match = re.search(pattern, intf)
       if not match:
          continue

       lc_mod = int(match.group(1))
       lc_port = int(match.group(2))

       type = getLcType(hdl, lc_mod, log)
       if not type:
          continue

       lc_ins = getLcInstance(lc_port, type, log)
       if lc_ins < 0:
          continue
          
       intf_dict[intf] = {}
       intf_dict[intf]['lc_mod'] = lc_mod
       intf_dict[intf]['lc_ins'] = lc_ins
       intf_dict[intf]['lc_port'] = lc_port

    return intf_dict

# Supprt seymour, snowbird, blackcomb, placid tor, and nagano tor
def getLcType(hdl, lc_mod, log):
    """
    params:
      lc_mod: int, module number from 1 to 16

    return:
       lc_type: 1 - seymore 
                2 - snowbird 
                3 - blackcomb|cypress
                4 - Placid Tor
                5 - Nagano Tor 
                0 - unknown
    """ 
    show_module = hdl.execute('show module {0}'.format(lc_mod))
    lc_type = 0
    if re.search(r'N9K-X9636PQ|N9k-X9636PQ|Seymour', show_module):
       lc_type = 1
    elif re.search(r'Cortina-Test-LC|Snowbird', show_module):
       lc_type = 2
    elif re.search(r'N9K-X9564(PX|TX)', show_module):
       lc_type = 3 
    elif re.search(r'N9K-C9396PX', show_module):
       lc_type = 4
    elif re.search(r'N9K-C93128TX', show_module):
       lc_type = 5
    else:
       log.error('Unknown linecard module type')
  
    return lc_type

# Supprt seymour, snowbird, blackcomb, placid tor, and nagano tor
def getLcInstance(lc_port, lc_type, log):
    """
    params:
      lc_port: int, front panel port #
      lc_type: int, 1 - seymore
                    2 - snowbird
                    3 - blackcomb|cypress
                    4 - placid tor
                    5 - nagano tor
    return:
       lc_ins: int, 0|1|2 or -1 for invalid input
    """
    lc_ins = -1
    if lc_type == 1:
       if 1 <= lc_port <= 12:
          lc_ins = 0
       elif 13 <= lc_port <= 24:
          lc_ins = 1
       elif 25 <= lc_port <= 36:
          lc_ins = 2
       else:
          log.error('Incorrect port: {0} given for seymore card .. Valid port number is from 1 to 36'.format(lc_port))
    elif lc_type == 2:
       if 1 <= lc_port <= 20:
          lc_ins = 1
       elif 21 <= lc_port <= 34:
          lc_ins = 0
       else:
          log.error('Incorrect port: {0} given for snowbird card .. Valid port number is from 1 to 34'.format(lc_port))
    elif lc_type == 3:
       if 1 <= lc_port <= 48:
          lc_ins = 0
       elif 49 <= lc_port <= 52:
          lc_ins = 1
       else:
          log.error('Incorrect port: {0} given for blackcomb card .. Valid port number is from 1 to 52'.format(lc_port))
    elif lc_type == 4:
       if 1 <= lc_port <= 48:
          lc_ins = 0
       else:
          log.error('Incorrect port: {0} given for placid tor .. Valid port number is from 1 to 48'.format(lc_port))
    elif lc_type == 5:
       if 1 <= lc_port <= 96:
          lc_ins = 0
       else:
          log.error('Incorrect port: {0} given for nagano tor .. Valid port number is from 1 to 96'.format(lc_port))
    else:
       log.error('Incorrect module type .. Valid lc_mod is from 1 to 5')
   
    return lc_ins 


def getDeviceType (hdl):
    """
    params:
      hdl: device handler
 
    return:
       dev_type: string, such as C9508, C93128TX, C9396PX
    """
    cmd_out = hdl.execute("show version | grep -i Chassis")
    pattern = 'Nexus[0-9]+ (C[0-9A-Z]+)'
    dev_type = ''
    match = re.search(pattern, cmd_out)    
    if match:
       dev_type = match.group(1)
    return dev_type


def getDir(hdl,log,*args):

    arggrammar={}
    #arggrammar['option']='-default bootflash: -choices ["bootflash:","debug:", "log:", "logflash:", "usb1:", "usb2:", "volatile:", "bootflash://sup-standby", "logflash://sup-standby", "usb1://sup-standby", "usb2://sup-standby"]'
    arggrammar['option']=''

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log) 
   
    if not ns.VALIDARGS:
        return {}

    showOutput=hdl.execute('dir {0}'.format(ns.option))

    returndict={}
    files=re.findall("\S+([0-9]+)\s+([a-zA-Z]+\s+[0-9]+\s+[0-9:]+\s+[0-9]+)\s+(\S+)",showOutput)
    for filename in files:
        returndict[filename[2]]={}
        returndict[filename[2]]['time']=filename[1]
        returndict[filename[2]]['size']=filename[0]

    bytedetails=re.findall("([0-9]+)\s+bytes\s+([a-z]+)",showOutput)
    for detail in bytedetails:
        returndict[detail[1]]=detail[0]

    return returndict
          
def getObflcleartime(hdl,log,*args):

    arggrammar={}
    arggrammar['module']='-type required -type int'

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if not ns.VALIDARGS:
       return {}

    hdl.hdl.sendline('show logging onboard module {0} obfl-history'.format(ns.module))
    prompts=['# $']
    hdl.hdl.expect(prompts,timeout=120)
    showoutput=hdl.hdl.before
    cleartime=re.findall('([A-Za-z]+)\s+([A-Za-z]+)\s+([0-9]+)\s+([0-9:]+)\s+([0-9]+)\s+:\s+OBFL\s+all\s+logs\s+cleared',showoutput)

    if not len(cleartime):
       return {}

    if len(cleartime[0]) != 5:
       return {}

    returndict={}
    returndict['day']=cleartime[0][0]
    returndict['month']=cleartime[0][1]
    returndict['date']=cleartime[0][2]
    returndict['time']=cleartime[0][3]
    returndict['year']=cleartime[0][4]

    return returndict

def getClock(hdl, log):

    showoutput = hdl.execute('show clock')
    curtime=re.findall('([0-9:]+)\.[0-9]+\s+([a-zA-Z]+)\s+([a-zA-Z]+)\s+([a-zA-Z]+)\s+([0-9]+)\s+([0-9]+)',showoutput)
    # 03:48:34.548 PST Tue Oct 08 2013

    if not len(curtime):
       return {}

    if len(curtime[0]) != 6:
       return {}

    returndict={}
    returndict['day']=curtime[0][2]
    returndict['month']=curtime[0][3]
    returndict['date']=curtime[0][4]
    returndict['time']=curtime[0][0]
    returndict['timezone']=curtime[0][1]
    returndict['year']=curtime[0][5]

    return returndict


def getModuleResetReason(hdl, log, *args):

    arggrammar={}
    arggrammar['module']='-required True -type int'     

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if not ns.VALIDARGS:
        return {}
 
    showoutput = hdl.execute('show system reset-reason module {0}'.format(ns.module)) 

    times=re.findall('usecs after ([A-Za-z]+\s+[A-Za-z]+\s+[0-9]+\s+[0-9:]+\s+[0-9]+)', showoutput)
    reasons=re.findall("eason\s*:\s+([^\r\n]+)",showoutput)
    services=re.findall('Service:\s+([\^\r\n]+)',showoutput)
    versions=re.findall('Version:\s+([\^\r\n]+)',showoutput)
    errorcodes=re.findall('Error code\s*:\s+([\^\r\n]+)',showoutput)
    serialnumbers=re.findall('Serial number\s*:\s+([\^\r\n]+)',showoutput)
    servicenames=re.findall('Service name\s*:\s+([\^\r\n]+)',showoutput)

    reasoncnt=max(len(times),len(reasons),len(services),len(versions),len(errorcodes),len(serialnumbers),len(servicenames))

    returndict=collections.OrderedDict()

    for i in range(reasoncnt):
        returndict[i]={}
        if i < len(times):
           returndict[i]['time']=times[i]
        if i < len(reasons):
           returndict[i]['reason']=reasons[i]
        if i < len(services):
           returndict[i]['service']=services[i]
        if i < len(versions):
           returndict[i]['version']=versions[i]
        if i < len(errorcodes):
           returndict[i]['erorcode']=errorcodes[i]
        if i < len(serialnumbers):
           returndict[i]['serialnumber']=serialnumbers[i]
        if i < len(servicenames):
           returndict[i]['servicename']=servicenames[i]

    return returndict

def getObflResetReason(hdl, log, *args):

    arggrammar={}
    arggrammar['module']='-required True -type int'     

    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    if not ns.VALIDARGS:
        return {}
 
    showoutput = hdl.execute('show logging onboard module {0} internal reset-reason'.format(ns.module)) 

    lcm_reasons=re.findall('Reset Reason \(LCM\):\s+([^\(]+)\([0-9]+\)\s+at time\s+(.*)',showoutput,flags=re.I|re.M)
    sw_reasons=re.findall('Reset Reason \(SW\):\s+([^\(]+)',showoutput,flags=re.I|re.M)
    hw_reasons=re.findall('Reset Reason \(HW\):\s+([^\(]+)\([0-9]+\)\s+at time\s+(.*)',showoutput,flags=re.I|re.M)

    indexes=max(len(lcm_reasons),len(sw_reasons),len(hw_reasons))

    returndict=collections.OrderedDict()

    for i in range(indexes):
        returndict[i]={}
        if i < len(lcm_reasons):
           returndict[i]['lcm_reason']=lcm_reasons[i] 
        if i < len(sw_reasons):
           returndict[i]['sw_reason']=sw_reasons[i] 
        if i < len(hw_reasons):
           returndict[i]['hw_reason']=hw_reasons[i] 

    return returndict

def getGoldResultDetailDict(hdl, log, *args):

    arggrammar={}
    arggrammar['module']='-type int -required True'
    arggrammar['test']='-type int -required True'

    ns = parserutils_lib.argsToCommandOptions(args, arggrammar, log)

    if not ns.VALIDARGS:
        return {}

    showoutput = hdl.execute('show diagnostic result module {0} test {1} detail'.format(ns.module,ns.test))

    rows=re.findall('([A-Za-z ]+)\-+>\s+([^\r\n]+)',showoutput,flags=re.I|re.M)
    returndict={}
    for row in rows:
        returndict[row[0].strip()]=row[1].strip()

    portresults=re.findall("([\.FIUAE])\s+",showoutput)
    if len(portresults) > 6:
        index=1
        returndict['perportresult']={}
        for result in portresults[6:]:
            returndict['perportresult'][index]=portresults[0]
            index=index+1

    return returndict

def getTransceiverDict(hdl,log,*args):

    arggrammar={}
    arggrammar['interface']='-required True'
   
    ns=parserutils_lib.argsToCommandOptions(args, arggrammar, log)

    if not ns.VALIDARGS:
        log.error("not valid interfaces passed")
        return {} 

    showoutput = hdl.execute ("show interface {0} transceiver details".format(ns.interface))

    params=re.findall("\s+([a-zA-Z ]+)is\s+([a-zA-Z0-9\- \+\/]+)",showoutput,flags=re.I|re.M)
    lanes=re.findall("Lane number:([0-9+])",showoutput,flags=re.I|re.I)

    returndict={}
    for param in params:
        returndict[param[0].strip()]=param[1].strip()

    if len(lanes):
       temperatures=re.findall("Temperature\s+([0-9\.\-]+)\s+C\s+([0-9\.\-]+)\s+C\s+([0-9\.\-]+)\s+C\s+([0-9\.\-]+)\s+C\s+([0-9\.\-]+)\s+C\s+",showoutput,flags=re.I|re.M)
       voltages=re.findall("Voltage\s+([0-9\.\-]+)\s+V\s+([0-9\.\-]+)\s+V\s+([0-9\.\-]+)\s+V\s+([0-9\.\-]+)\s+V\s+([0-9\.\-]+)\s+V\s+",showoutput,flags=re.I|re.M)
       currents=re.findall("Current\s+([0-9\.\-]+)\s+mA\s+([0-9\.\-]+)\s+mA\s+([0-9\.\-]+)\s+mA\s+([0-9\.\-]+)\s+mA\s+([0-9\.\-]+)\s+mA\s+",showoutput,flags=re.I|re.M)
       txpowers=re.findall("Tx Power\s+([0-9\.\-]+)\s+dBm\s+([0-9\.\-]+)\s+dBm\s+([0-9\.\-]+)\s+dBm\s+([0-9\.\-]+)\s+dBm\s+([0-9\.\-]+)\s+dBm\s+",showoutput,flags=re.I|re.M)
       rxpowers=re.findall("Rx Power\s+([0-9\.\-]+)\s+dBm\s+\-+\s+([0-9\.\-]+)\s+dBm\s+([0-9\.\-]+)\s+dBm\s+([0-9\.\-]+)\s+dBm\s+([0-9\.\-]+)\s+dBm\s+",showoutput,flags=re.I|re.M)

       if len(lanes):
           returndict['lanes']={}

       for lane in lanes:
           returndict['lanes'][int(lane)]={}
           if int(lane)-1 < len(temperatures): 
               returndict['lanes'][int(lane)]['temperature']=temperatures[int(lane)-1]
           if int(lane)-1 < len(voltages): 
               returndict['lanes'][int(lane)]['voltage']=voltages[int(lane)-1]
           if int(lane)-1 < len(currents): 
               returndict['lanes'][int(lane)]['current']=currents[int(lane)-1]
           if int(lane)-1 < len(txpowers):
               returndict['lanes'][int(lane)]['txpowers']=txpowers[int(lane)-1]
           if int(lane)-1 < len(rxpowers): 
               returndict['lanes'][int(lane)]['rxpowers']=rxpowers[int(lane)-1]

    return returndict

# Supprt seymour, snowbird, blackcomb, placid tor, and nagano tor
def getBcmPort(lc_port, lc_type, log):
    """
    params:
      lc_port: int, front panel port #
      lc_type: int, 1 - seymore
                    2 - snowbird
                    3 - blackcomb
                    4 - placid tor
                    5 - nagano tor
    return:
       bcm_port: int, for instance: 0 in xe0 
    """
    bcm_port = -1
    if lc_type == 1:
       if 1 <= lc_port <= 12:
          bcm_port = lc_port - 1
       elif 13 <= lc_port <= 24:
          bcm_port = lc_port - 13
       elif 25 <= lc_port <= 36:
          bcm_port = lc_port - 25
    elif lc_type == 2:
       if 1 <= lc_port <= 20:
          bcm_port = lc_port - 1 
       elif 21 <= lc_port <= 34:
          bcm_port = lc_port - 21 
       else:
          log.error('Incorrect port: {0} given for snowbird card .. Valid port number is from 1 to 34'.format(lc_port))
    elif lc_type == 3:
       if 1 <= lc_port <= 48:
          bcm_port = lc_port - 1
       elif 49 <= lc_port <= 52:
          bcm_port = lc_port - 49
       else:
          log.error('Incorrect port: {0} given for blackcomb card .. Valid port number is from 1 to 52'.format(lc_port))
    elif lc_type == 4:
       if 1 <= lc_port <= 48:
          bcm_port = lc_port -1
       else:
          log.error('Incorrect port: {0} given for placid tor .. Valid port number is from 1 to 48'.format(lc_port))
    elif lc_type == 5:
       if 1 <= lc_port <= 96:
          bcm_port = lc_port -1
       else:
          log.error('Incorrect port: {0} given for nagano tor .. Valid port number is from 1 to 96'.format(lc_port))
    else:
       log.error('Incorrect module type .. Valid lc_mod is from 1 to 5')

    return bcm_port


def CookIxiaTiTrafficStats(ti_traffic_stats, log):
  '''Convert ti_traffic_stats string to dict.

  Args:
    ti_traffic_stats: big str returned from ixia_lib

  Returns:
    dict.
  '''
  pat_list = ((':', '%'),  # time stamp xx:yy:zz -> xx%yy%zz
              ('} {', ','),
              ('{{', '{'),
              ('}}', '}'),
              (' ', ': '),)
 
  ti_match = re.search(r'{traffic_item.*', ti_traffic_stats)
  if not ti_match:
    log.error('Unexpected format of traffic item stats.')
    return
  s = ti_match.group()

  pat_ti = '{([^{]*)} {{[t|r]x'
  ti_list = re.findall(pat_ti, s)
  ti_names = {}
  for ti in ti_list:
    ti_old = '{' + ti + '}'
    ti_tmp = ti.replace(' ', '_')
    ti_names[ti_tmp] = '\'' + ti + '\''
    s = s.replace(ti_old, ti_tmp)

  for pat in pat_list:
    s = s.replace(pat[0], pat[1])

  for ti_tmp in ti_names:
    s = s.replace(ti_tmp, ti_names[ti_tmp])

  try:
    ti_dict = yaml.load(s)
    return ti_dict['traffic_item']
  except ValueError:
    log.error('Unexpected format of traffic item stats.')


#======================================================================================#
# getEigrpNeighborDict - Method to get Ip Eigrp neighbors
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
# optional args
# CLI accepts only one of the optional arguments - vrf or interface
# vrf - vrf name to get Ip eigrp neighbor dict in non-default vrf 
# interfaces - physical or vlan or port-channel
#              Example: '-interface vlan20' or 'interface eth3/1' or
#                       '-vrf test'  or '-interface po10'
#======================================================================================#
def getEigrpNeighborDict(hdl,log,*args):
        arggrammer={}
        arggrammer['vrf']='-type str'
        arggrammer['interface']=' -type str'
        arggrammer['mutualExclusive'] =[('vrf','interface')]
        ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
        sw_cmd="show ip eigrp neighbors  "
        if ns.vrf:
              sw_cmd=sw_cmd + "vrf " + ns.vrf
        if ns.interface:
            sw_cmd= sw_cmd + " " + str(ns.interface)

        output=hdl.execute(sw_cmd)

        '''sys01-eor1# sh ip eigrp neighbors po101
           IP-EIGRP neighbors for process 65535 VRF default
           H   Address                 Interface       Hold  Uptime  SRTT   RTO  Q  Seq
                                                       (sec)         (ms)       Cnt Num
           9   20.1.1.2                Po101           14   01:36:50  3    50    0   232107'''

        pat='([0-9]+)[ \t]+({0})[ \t]+({2})[ \t]+([0-9]+)[ \t]+({1})[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)'.format(rex.IPv4_ADDR,rex.UPTIME,rex.INTERFACE_NAME)
        neighbor_list=re.findall( pat, output, flags=re.M )
        neighbor_dict=convertListToDict(neighbor_list,['H','Address','Interface','Hold','Up_Time','SRTT','RTO','Q','Seq_num'],['Address'])
        if len(neighbor_list)==0:
             msg='No IP Eigrp neighbors found on {0}'.format(hdl.switchName)
             print(msg)
             log.info(msg)
        return neighbor_dict


#======================================================================================#
# getEigrpv6NeighborDict - Method to get Eigrpv6 neighbors information
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
# optional args
# CLI accepts only one of the optional arguments - vrf or interface
# vrf - vrf name to get ipv6 eigrp neighbor dict in non-default vrf 
# interfaces - physical or vlan or port-channel
#              Example: '-interface vlan20' or 'interface eth3/1' or
#                       '-vrf test'  or '-interface po10'
# primary key of dict is (Neighbor_ID,Interface)
#======================================================================================#
def getEigrpv6NeighborDict(hdl,log,*args):
        arggrammer={}
        arggrammer['vrf']='-type str'
        arggrammer['interface']=' -type str'
        arggrammer['mutualExclusive'] =[('vrf','interface')]
        ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
        sw_cmd="show ipv6 eigrp neighbors  "
        if ns.vrf:
              sw_cmd=sw_cmd + "vrf " + ns.vrf
        if ns.interface:
            sw_cmd= sw_cmd + " " + str(ns.interface)

        output=hdl.execute(sw_cmd)
        pattern="([0-9]+)"
        pattern=pattern+"[ \t]+("+rex.LINK_LOCAL_IPv6_ADDR+")"
        pattern=pattern+"[ \t]+("+rex.INTERFACE_NAME+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.UPTIME+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        pattern=pattern+"[ \t]+("+rex.NUM+")"
        neighbor_list=re.findall( pattern, output, flags=re.M )

        log.info("Eigrpv6 Neighbor List: " + str(neighbor_list))
        neighbor_dict=convertListToDict(neighbor_list,['H','Address','Interface','Hold','Up_Time','SRTT','RTO','Q','Seq_num'],['Address','Interface'])
        log.info("Eigrpv6 Neighbor Dict: " + str(neighbor_dict))
        if len(neighbor_list)==0:
             msg='No Ipv6 Eigrp neighbors found on {0}'.format(hdl.switchName)
             print(msg)
             log.info(msg)
        return neighbor_dict

#======================================================================================#
# getDhcpRelayDict - Method to get DHCP Relay Address information
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
#======================================================================================#

def getDhcpRelayDict(hdl,log,*args):

    '''
       Returns dhcprelayadddict:
          {'status': 'enabled', 'cisco_suboption': 'disabled', 'vpn_suboption': 'disabled', 'smart_relay': 'disabled', 'option_82': 'enabled'
           'Ethernet4/33': [('118.2.1.12', 'default'), ('118.2.1.12', 'green')], 
           'Ethernet4/34': [('118.2.1.13', 'default')]}
    '''

    cmd = "show ip dhcp relay "
   
    output = hdl.execute(cmd)
    dhcprelayadddict={}

    match = re.search('DHCP relay service is ({0})'.format(rex.ALPHA),output)
    if match:
       dhcprelayadddict['status'] = match.group(1)
    match = re.search('Insertion of option 82 is ({0})'.format(rex.ALPHA),output)
    if match:
       dhcprelayadddict['option_82'] = match.group(1)
    match = re.search('Insertion of VPN suboptions is ({0})'.format(rex.ALPHA),output)
    if match:
       dhcprelayadddict['vpn_suboption'] = match.group(1)
    match = re.search('Insertion of cisco suboptions is ({0})'.format(rex.ALPHA),output)
    if match:
       dhcprelayadddict['cisco_suboption'] = match.group(1)
    match = re.search('Global smart-relay is ({0})'.format(rex.ALPHA),output)
    if match:
       dhcprelayadddict['smart_relay'] = match.group(1)

    for line in output.split('\r\n'):
       match = re.search('({0})[ \t]+({1})(?:[ \t]+({2}))?'.format(rex.INTERFACE_NAME,rex.IPv4_ADDR,rex.VRF_NAME),line)
       if match:
          int_name = match.group(1)
          relay_address = match.group(2)
          if match.group(3) == None:
             vrf = 'default'
          else:
             vrf = match.group(3)
          if not dhcprelayadddict.has_key(int_name):
             dhcprelayadddict[int_name] = []
          dhcprelayadddict[int_name].append((relay_address,vrf))

    log.debug("DHCP Relay Dict: " + str(dhcprelayadddict))
    return dhcprelayadddict

#======================================================================================#
# getDhcpv6RelayDict - Method to get DHCP Relay Address information
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
#======================================================================================#

def getDhcpv6RelayDict(hdl,log,*args):

    '''
       Returns dhcpv6relayadddict:
       {'status': 'Enabled', 'cisco_option': 'Enabled', 'vpn_option': 'Enabled', 'source_interface': 'Ethernet4/33'
        'Ethernet4/33': [('2118:2::12', '---', 'default'),'2118:20::12', '---', 'default')], 
        'Ethernet4/34': [('2118:2::13', '---', 'default')]}
    '''

    cmd = "show ipv6 dhcp relay "
   
    output = hdl.execute(cmd)
    dhcpv6relayadddict={}

    match = re.search('DHCPv6 relay service : ({0})'.format(rex.ALPHA),output)
    if match:
       dhcpv6relayadddict['status'] = match.group(1)
    match = re.search('Relay source interface : ({0})'.format(rex.INTERFACE_NAME),output)
    if match:
       dhcpv6relayadddict['source_interface'] = match.group(1)
    match = re.search('Insertion of VPN options : ({0})'.format(rex.ALPHA),output)
    if match:
       dhcpv6relayadddict['vpn_option'] = match.group(1)
    match = re.search('Insertion of CISCO options : ({0})'.format(rex.ALPHA),output)
    if match:
       dhcpv6relayadddict['cisco_option'] = match.group(1)

    for line in output.split('\r\n'):
       match = re.search('Interface[ \t]+({0})'.format(rex.INTERFACE_NAME),line)
       if match:
          int_name = match.group(1)
       match = re.search('({0})[ \t]+({1}|[\-]+)?(?:[ \t]+({2}))?'.format(rex.IPv6_ADDR,rex.INTERFACE_NAME,rex.VRF_NAME),line)
       if match:
          relay_address = match.group(1)
          dest_interface = match.group(2)
          if match.group(3) == None:
             vrf = 'default'
          else:
             vrf = match.group(3)
          if not dhcpv6relayadddict.has_key(int_name):
             dhcpv6relayadddict[int_name] = []
          dhcpv6relayadddict[int_name].append((relay_address,dest_interface,vrf))

    log.debug("DHCPv6 Relay Dict: " + str(dhcpv6relayadddict))
    return dhcpv6relayadddict

#======================================================================================#
# getDhcpRelayStatsDict - Method to get DHCP Relay Statistics information
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
#======================================================================================#


def getDhcpRelayStatsDict(hdl,log,*args):

    '''
    Returns dhcprelaystatdict{}:
          {'Decline': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]),
           'Ack':     OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]), 
           'Request': OrderedDict([('Rx', '156'), ('Tx', '0'), ('Drops', '156')]),
           'Inform':  OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]),
           'Release': OrderedDict([('Rx', '155'), ('Tx', '0'), ('Drops', '155')]),
           'Offer':   OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]), 
           'Nack':    OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]),
           'Discover':OrderedDict([('Rx', '314'), ('Tx', '0'), ('Drops', '314')]),
           'Total':   OrderedDict([('Rx', '625'), ('Tx', '0'), ('Drops', '625')])  
           'Non_DHCP_Drop': '0', 'DHCP_L3_FWD_Tx': '0', 'Non_DHCP_Rx': '0',  'Unknown vrf or interface for server': '0', 'Invalid DHCP message type': '0',  'Non_DHCP_Fx': '0', 'Total Packets Forwarded': '0', 
           'Tx failure towards server': '0', 'DHCP Relay not enabled': '0', 'Interface error': '625', 'DHCP_L3_FWD_Fx': '0', 'Total Packets Received': '0',  'Option 82 validation failed': '0', 
           'Max hops exceeded': '0', 'Tx failure towards client': '0', 'Packet Malformed': '0', 'Unknown output interface': '0', 'Total Packets Dropped': '0', 'DHCP_L3_FWD_Drop': '0', }
    '''

    arggrammer={}
    arggrammer['interface']=' -type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
    sw_cmd="show ip dhcp relay statistics  "
    if ns.interface:
        sw_cmd= sw_cmd + " interface  " + str(ns.interface)

    output=hdl.execute(sw_cmd)

    dict = {}
    #Collect per Server Stats when interface is given
    if ns.interface:
        match = re.findall('({0})[ \t]+(?:({2})[ \t]+)?({1})[ \t]+({1})'.format(rex.IPv4_ADDR,rex.NUM,rex.VRF_NAME),output)
        dict=convertListToDict(match,['Server','VRF','Request','Response'],['Server'])

    #Collect Message type and Rx/Tx/Drops for each
    match = re.findall('({0})(?:\(\*\))?[ \t]+({1})[ \t]+({1})[ \t]+({1})'.format(rex.ALPHA,rex.NUM),output,re.I)
    dict.update(convertListToDict(match,['Message_Type','Rx','Tx','Drops'],['Message_Type']))

    #Collect Drops stats
    match = re.findall('(.*{0})[ \t]+\:[ \t]+({1})'.format(rex.ALPHA,rex.NUM),output,re.I)
    dict.update(convertListToDict(match,['Message_Type','Drops'],['Message_Type']))

    partial_output = output.split('Non DHCP:');
    match = re.findall('Total Packets Received +: +([0-9])+',partial_output[0],re.I)
    if match:
       dict.update({'DHCP_L3_FWD_Tx':match[0][0]})
    match =re.findall('Total Packets Forwarded +: +([0-9])+',partial_output[0],re.I)
    if match:
       dict.update({'DHCP_L3_FWD_Fx':match[0][0]})
    match = re.findall('Total Packets Dropped +: +([0-9])+',partial_output[0],re.I)
    if match:
       dict.update({'DHCP_L3_FWD_Drop':match[0][0]})
    match = re.findall('Total Packets Received +: +([0-9])+',partial_output[1],re.I)
    if match:
       dict.update({'Non_DHCP_Rx':match[0][0]})
    match = re.findall('Total Packets Forwarded +: +([0-9])+',partial_output[1],re.I)
    if match:
       dict.update({'Non_DHCP_Fx':match[0][0]})
    match = re.findall('Total Packets Dropped +: +([0-9])+',partial_output[1],re.I)
    if match:
       dict.update({'Non_DHCP_Drop':match[0][0]})
    return dict

#======================================================================================#
# getDhcpv6RelayStatsDict - Method to get DHCP Relay Statistics information
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
#======================================================================================#


def getDhcpv6RelayStatsDict(hdl,log,*args):

    '''
    Returns dhcprelaystatsdict{}:
          {'DECLINE': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]),
           'CONFIRM': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]), 
           'FWD':     OrderedDict([('Rx', '0'), ('Tx', '795'), ('Drops', '0')]), 
           'UNKNOWN': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]), 
           'REQUEST': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]), 
           'REBIND':  OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]),
           'RENEW':   OrderedDict([('Rx', '795'), ('Tx', '0'), ('Drops', '0')]),
           'SOLICIT': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]), 
           'RELEASE': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]), 
           'REPLY':   OrderedDict([('Rx', '85'), ('Tx', '0'), ('Drops', '0')]), 
           'RECONFIGURE': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]),
           'ADVERTISE': OrderedDict([('Rx', '0'), ('Tx', '0'), ('Drops', '0')]), 
           'Total': OrderedDict([('Rx', '880'), ('Tx', '880'), ('Drops', '0')])'Packet validation fails': '0', 'Interface error': '0', 'VPN Option Disabled': '0', 'IPv6 addr not configured': '0', 
           'Option insertion failed': '0', 'DHCPv6 Relay is disabled': '0', 'Max hops exceeded': '0',  'Unknown output interface': '0',  'IPv6 extn headers present': '0', 'Replies from client': '0', }
    '''

    arggrammer={}
    arggrammer['interface']=' -type str'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
    sw_cmd="show ipv6 dhcp relay statistics "
    if ns.interface:
        sw_cmd= sw_cmd + "interface " + str(ns.interface)

    output=hdl.execute(sw_cmd)

    dict = {}
    #Collect per Server Stats when interface is given
    if ns.interface:
        match = re.findall('({0})[ \t]+(?:({2}|[\-]+)[ \t]+)?(?:({3}|[\-]+)[ \t]+)?({1})[ \t]+({1})'.format(rex.IPv6_ADDR,rex.NUM,rex.VRF_NAME,rex.INTERFACE_NAME),output)
        dict=convertListToDict(match,['Server','VRF','dest_intf','Request','Response'],['Server'])

    #Collect Message type and Rx/Tx/Drops for each
    match = re.findall('({0})[ \t]+({1})[ \t]+({1})[ \t]+({1})'.format(rex.ALPHA,rex.NUM),output,re.I)
    dict.update(convertListToDict(match,['Message_Type','Rx','Tx','Drops'],['Message_Type']))

    #Collect Drops stats
    match = re.findall('(.*{0})[ \t]+\:[ \t]+({1})'.format(rex.ALPHA,rex.NUM),output,re.I)
    dict.update(convertListToDict(match,['Message_Type','Drops'],['Message_Type']))

    return dict



def getFabricConnectivity(hdl,log,*args):

    '''
    Returns FabricConnectivity as ordereddict

    First level key is Asic unit
    Second level key is Hglink
    Third level key is peer module
    Fourth level key is peer unit
    Fifth level value is peer Hglinke

    OrderedDict([('0', OrderedDict([('HG00', OrderedDict([('1', '0')])), ('HG03', OrderedDict([('1', '0')])), ('HG01', OrderedDict([('1', '1')])), ('HG04', OrderedDict([('1', '1')])), ('HG02', OrderedDict([('1', '2')])), ('HG05', OrderedDict([('1', '2')])), ('HG06', OrderedDict([('2', '0')])), ('HG08', OrderedDict([('2', '0')])), ('HG09', OrderedDict([('2', '0')])), ('HG11', OrderedDict([('2', '0')])), ('HG07', OrderedDict([('2', '1')])), ('HG10', OrderedDict([('2', '1')])), ('HG12', OrderedDict([('3', '0')])), ('HG14', OrderedDict([('3', '0')])), ('HG15', OrderedDict([('3', '0')])), ('HG17', OrderedDict([('3', '0')])), ('HG13', OrderedDict([('3', '1')])), ('HG16', OrderedDict([('3', '1')])), ('HG18', OrderedDict([('4', '0')])), ('HG20', OrderedDict([('4', '0')])), ('HG21', OrderedDict([('4', '0')])), ('HG23', OrderedDict([('4', '0')])), ('HG19', OrderedDict([('4', '1')])), ('HG22', OrderedDict([('4', '1')]))]))])
       

    
    '''

    arggrammar={}
    arggrammar['module']='-type int -required True'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log) 
    returndict=collections.OrderedDict()

    #print ns
    if not ns.VALIDARGS:
        log.error("Parser error, verify {0} against {1}".format(args,arggrammar)) 
        return returndict

    showoutput = hdl.execute('show system internal fabric connectivity module {0}'.format(ns.module))

    if ns.module in range(1,17):
        lines=re.findall("[0-9]+\s+([0-9]+)\s+(HG[0-9]+)\s+([\-A-Z0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(HG[0-9]+)",showoutput)
        #print lines
        for line in lines:
            if line[0] not in returndict.keys():
                returndict[line[0]]=collections.OrderedDict()
            returndict[line[0]][line[1]]=collections.OrderedDict()
            returndict[line[0]][line[1]][line[3]]=collections.OrderedDict()
            returndict[line[0]][line[1]][line[3]][line[4]]=line[5]
    elif ns.module in range(21,27):
        lines=re.findall("[0-9]+\s+([0-9]+)\s+(HG[0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(HG[0-9]+)\s+([\-A-Z0-9]+)",showoutput)
        #print lines
        for line in lines:
            if line[0] not in returndict.keys():
                returndict[line[0]]=collections.OrderedDict()
            returndict[line[0]][line[1]]=collections.OrderedDict()
            returndict[line[0]][line[1]][line[2]]=collections.OrderedDict()
            returndict[line[0]][line[1]][line[2]][line[3]]=line[4]
    else:
        log.error("Module is {0} but should be between 1 to 16 or 21 to 26".format(ns.module))

    return returndict 

#======================================================================================#
# getLicenseUsage - Method to get License Info
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
#======================================================================================#
def getLicenseUsage(hdl,log):

    '''
       Returns licenseDict:
          {'Feature': 'LAN_ENTERPRISE_SERVICES_PKG', 'Ins': 'Yes/No', 'Status': 'In use/Never', 'Expiry': 'Never/ '
    '''

    sw_cmd="show license usage"
    output=hdl.execute(sw_cmd)
    licenseDict = {}

    #Collect the license o/p
    info = re.split('\n',output)    
    match = re.findall('(\w+)\s+(\w+)\s+[-]\s+([\w+\s*\w+]+)\s+\w+',info[3],re.I)
    result = licenseDict.update(convertListToDict(match,['Feature','Ins','Status']))
    if licenseDict['Ins'] == 'Yes':
        licenseDict = {}
        match = re.findall('(\w+)\s+(\w+)\s+[-]\s+([\w+\s*\w+]+)\s+(\w+)',info[3],re.I)
        result = licenseDict.update(convertListToDict(match,['Feature','Ins','Status','Expiry']))
    return licenseDict   

#======================================================================================#
# getLicenseApps - Method to get what all apps are using the license
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
# feature - license feature
#       
#======================================================================================#
def getLicenseApp(hdl,log,*args):

    '''
       Returns licenseDict:
          {'Application': 'bgp'
    '''
    arggrammer={}
    arggrammer['feature']=' -type str -default LAN_ENTERPRISE_SERVICES_PKG'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
    returndict=collections.OrderedDict()
    if not ns.VALIDARGS:
        log.error("Parser error, verify {0} against {1}".format(args,arggrammar))
        return returndict
        
    sw_cmd="show license usage {0}".format(ns.feature)
    output=hdl.execute(sw_cmd)
    licenseDict = {}

    #Collect the license o/p
    if output:
        match = re.findall('({0})'.format(rex.ALPHANUM),output)
        return match
    else:
        return False    

#======================================================================================#
# checkLicense - Method to get License Info
#       
# mandatory args
# hdl - switch handle object from icon
# log - harness/python logging object
#       
#======================================================================================#
def checkLicense(hdl,log):

    '''
       Returns True/False based on whether License is installed or not:
    '''

    sw_cmd="show license usage"
    output=hdl.execute(sw_cmd)

    #Collect the license o/p
    match = re.search('yes',output,re.I)
    if match:
        log.info("License is installed")
        return True
    else:
        log.info("License is not installed")
        return False


#======================================================================================#
def verifyLicenseStatus(hdl,log,*args):


    '''
       Verify License with the status   
    '''
    arggrammer={}
    arggrammer['feature']=' -type str -default LAN_ENTERPRISE_SERVICES_PKG'
    arggrammer['status']=' -type str -default Unused'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammer,log,'namespace')
    returndict=collections.OrderedDict()
    if not ns.VALIDARGS:
        log.error("Parser error, verify {0} against {1}".format(args,arggrammar))
        return returndict

    sw_cmd="show license usage"
    output=hdl.execute(sw_cmd)
    licenseDict = {}
    rexp = '{0}\s*[A-Za-z\s]*[\-]+\s*{1}*\s+[A-Za-z]*'.format(ns.feature,ns.status) 
    #Collect the license o/p
    if output:
        match = re.search(rexp,output)
        if match:
           log.info("License is matched with expected status")
           testResult('pass', 'License is matched with expected status',log)
        else:
           log.error("License feature {0} is not matching with the expected status {1} , Please check the logs".format(ns.feature,ns.status))    
           fail_msg = ('License feature {0} is not matching with the expected status {1} , Please check the logs'.format(ns.feature,ns.status)) 
           testResult('fail', fail_msg ,log)
    else:
        log.error("show license CLI is not giving any output")
        testResult('fail','show license CLI is not giving any output',log) 


#======================================================================================#
####
#MSDC_PRADN
####


def getForwardingIPv4RouteDetail(hdl, log, route,*args):

        arggrammar={}
        arggrammar['routeIp']=''
        #self.route=route
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        cmd="sh forwarding ipv4 route detail | section {0}".format(route)
        pattern="Prefix [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/\d+, No of paths:\s+(\d+)"
        pattern1="([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([a-z\-0-9\/]+)"
        cmd_out = hdl.execute(cmd)
        cmd_out_list=cmd_out.split("\n")
        #print cmd_out_list
        routeip=route
        log.info("routeIp:{}".format(routeip))
        route = {}
        nexthop=[]
        nexthopInt=[]
        route[routeip] = {}
        #for index in range(0,len(cmd_out_list)):
        #print cmd_out_list[index]
        match1=re.search(pattern, cmd_out)
        route[routeip]['Paths']=match1.group(1)
        for cmd in cmd_out_list:
          match2=re.findall(pattern1, cmd)
          log.info('group1:{},match:{},cmd:{}'.format(match1.group(1),match2,cmd))
          if  len(match2) != 0:
            for mat in match2:
#            match2=strtolist(match2.join)
              nexthop.append(mat[0])
              nexthopInt.append(mat[1])
#        for item in match2:
#            item=item.split( )
#            print item[0]
#            nexthop.append(item[0])
#            nexthopInt.append(item[1])
        route[routeip]['nexthop']=nexthop
        route[routeip]['nexthopInt']=nexthopInt
        return route


def getIpv4BgpSessionDict(hdl, log, *args):
      #Total peers 6, established peers 4
      #ASN 500
      #VRF default, local ASN 500
      #peers 6, established peers 4, local router-id 3.9.1.2
      #State: I-Idle, A-Active, O-Open, E-Established, C-Closing, S-Shutdown

      #Neighbor        ASN    Flaps LastUpDn|LastRead|LastWrit St Port(L/R)  Notif(S/R)
      #3.9.1.1           200 1     03:11:01|00:00:23|00:00:25 E  13361/179  0/0
      #4.9.1.1           200 0     00:30:45|00:00:14|00:00:14 E  64052/179  0/0
      #9.1.1.2           700 0     03:45:23|never   |never    A  0/0        0/0
      #1012::2           700 0     03:45:23|never   |never    I  0/0        0/0
      arggrammar={}
      arggrammar['vrf']='-type str'
      cmd = 'show bgp sessions'
      parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
      if parse_output.vrf:
         cmd = cmd +" " + 'vrf ' + parse_output.vrf
      #pattern='([\d\.\:]+)\s+\d+\s+\d+\s+[\d\:\|a-zA-Z]+\s+(\S+)\s+[\d\/]+'
      pattern='([\d\.\:]+)\s+\d+\s+\d+\s+[0-9a-z\d\|\:\s\.]+\s+(\S+)\s+[\d\/]+'
      cmd_out = hdl.execute(cmd)
      cmd_out_list=cmd_out.split("\n")
      #print cmd_out_list
      neighbor = {}
      for index in range(0,len(cmd_out_list)): 
        #print cmd_out_list[index]
        bgpSession_match = re.search(pattern, cmd_out_list[index])
        if bgpSession_match:
           neighbor_ip = bgpSession_match.group(1)
           neighbor[neighbor_ip]={}
           neighbor[neighbor_ip]['state']=bgpSession_match.group(2)            
      #return convertListToDict(bgpSession_match,['Neighbor','St'],['Neighbor'])
      return neighbor 

def getIpv4FromV6BgpSummaryDict(hdl, log, *args):

    # Get the IPv4 BGP neighbor summary in dictionary format
    # Usage:0
    # getIpv4BgpSummaryDict(hdl,log, '-vrf all' )
    # getIpv4BgpSummaryDict(hdl,log)


    # Sample Output
    #Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
    #3.10.1.1        4   200   11631   11644   145912    0    0    3d22h 1000
    #4.10.1.1        4   200   11643   11664   145912    0    0 16:43:59 0
    #10.1.1.2        4   800   12957   11246   145912    0    0 00:02:58 0
    #1014::2         4   800    7868    8024   145912    0    0 00:02:47 1000

    arggrammar={}
    arggrammar['vrf']='-type str'
    cmd = 'show ipv6 bgp summary '
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.vrf:
        cmd = cmd + " "+ 'vrf ' + parse_output.vrf
    pattern="([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+[\da-zA-Z\:\s]+\s+(\d+)"
    cmd_out = hdl.execute(cmd)
    cmd_out_list=cmd_out.split("\n")
    #print cmd_out_list
    neighbor = {}
    for index in range(0,len(cmd_out_list)):
        #print cmd_out_list[index]
        bgpv4matchList = re.search(pattern, cmd_out_list[index])
        if bgpv4matchList:
             neighbor_ip = bgpv4matchList.group(1)
             neighbor[neighbor_ip]={}
             neighbor[neighbor_ip]['PfxRcd']=bgpv4matchList.group(2)
      #return convertListToDict(bgpSession_match,['Neighbor','St'],['Neighbor'])
    return neighbor 


def getIpv6FromV4BgpSummaryDict(hdl, log, *args):

    # Get the IPv4 BGP neighbor summary in dictionary format
    # Usage:0
    # getIpv4BgpSummaryDict(hdl,log, '-vrf all' )
    # getIpv4BgpSummaryDict(hdl,log)


    # Sample Output
    #Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
    #3.10.1.1        4   200   11631   11644   145912    0    0    3d22h 1000
    #4.10.1.1        4   200   11643   11664   145912    0    0 16:43:59 0
    #10.1.1.2        4   800   12957   11246   145912    0    0 00:02:58 0
    #1014::2         4   800    7868    8024   145912    0    0 00:02:47 1000

    arggrammar={}
    arggrammar['vrf']='-type str'
    cmd = 'show ip bgp summary '
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if parse_output.vrf:
        cmd = cmd + " "+'vrf ' + parse_output.vrf
    #pattern="([0-9A-Fa-f]+:[0-9A-Fa-f:]+)\s+[\da-zA-Z\:\s]+"
    pattern="([0-9A-Fa-f]+:[0-9A-Fa-f:]+)\s+[\da-zA-Z\:\s]+\s+(\d+)"
    cmd_out = hdl.execute(cmd)
    cmd_out_list=cmd_out.split("\n")
    #print cmd_out_list
    neighbor = {}
    for index in range(0,len(cmd_out_list)):
        #print cmd_out_list[index]
        bgpv4matchList = re.search(pattern, cmd_out_list[index])
        if bgpv4matchList:
             neighbor_ip = bgpv4matchList.group(1)
             neighbor[neighbor_ip]={}
             neighbor[neighbor_ip]['PfxRcd']=bgpv4matchList.group(2)
      #return convertListToDict(bgpSession_match,['Neighbor','St'],['Neighbor'])
    return neighbor
    #bgpv6matchList=ddre.findall(pattern,cmd_out)
    #return bgpv6matchList


def getBgpV6RouteSummary(hdl, log, *args):
    
    # Sample Output
    #IPv6 Routing Table for VRF "default"
    #Total number of routes: 1000
    #Total number of paths:  1000
    #Total number of multicast paths:  0

    #Unicast paths:
    #Best paths per protocol:      Backup paths per protocol:
       #bgp-500        : 1000         None

    #Number of routes per mask-length:
       #/64: 1000  

    arggrammar={}
    arggrammar['vrf']='-type str'
    cmd = 'show ipv6 route bgp summary'
    parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    #if parse_output.vrf:
    #    cmd = cmd + " " +'vrf ' + parse_output.vrf
    pattern="Total number of routes:\s+(\d+)"
    cmd_out = hdl.execute(cmd)
    totalroutes=re.search(pattern,cmd_out)
    return totalroutes.group(1)

def getBgpRouteASPaths(hdl,route, log, *args):
    #BGP routing table entry for 70.1.1.0/24, version 51651
    #Paths: (4 available, best #2)
    #Flags: (0x08009a) on xmit-list, is in urib, is best urib route
    #Multipath: eBGP
    #
    #Path type: external, path is valid, not best reason: newer EBGP path, multipath, in rib
    #AS-Path: 500 64512 , path sourced external to AS
    #1007::2 (metric 0) from 1007::2 (3.9.1.2)
    #Origin IGP, MED not set, localpref 100, weight 0
    arggrammar={}
    cmd = 'show ip bgp {0}'.format(route)
    pattern="AS-Path:\s+([\d\s]+)"
    out = hdl.execute(cmd)
    AsPathList=re.findall(pattern,out)
    return AsPathList

def portChannelInternalDict(hdl,log):
    show_po = hdl.execute('show port-channel internal sdb')
    exp = 'Po(\d+)\s+(\S+)\s+\d+\s+(\S+)\s+\d+\s+\d+\s+([01])'
    int_info = re.findall(exp,show_po,re.I|re.M)
    po_int_dict = {}
    po_int_dict =convertListToDict(int_info,['PO','ifIndex','status','Susp-Dis'],'PO')
    return po_int_dict

def processCpu(hdl,log):
    show_processes = hdl.execute('show processes cpu | no-more')
    exp = '(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)%\s+(\S+)'
    process_list = re.findall(exp,show_processes,re.I|re.M)
    process_dict = {}
    process_dict = convertListToDict(process_list,['pid','runtime','invoked','usec','sec','pname'],'pname')
    return process_dict

def processCpufromLinux(hdl,log):
    show_processes = hdl.execute('ps -eo pcpu,pid,user,args | sort -r -k1')
    exp = '(\S+)\s+(\d+)\s+(\S+)\s+(\S+).*\n'
    process_list = re.findall(exp,show_processes,re.I|re.M)
    process_dict = {}
    process_dict = convertListToDict(process_list,['sec','pid','user','pname'],'pname')
    for var in process_dict.keys():
        mt1=re.search('\/isan\/bin\/(\S+)',var)
        if mt1:
            process_dict[mt1.group(1)]=process_dict[var]
            del process_dict[var]
        mt2=re.search('\/isan\/sbin\/(\S+)',var)
        if mt2:
            process_dict[mt2.group(1)]=process_dict[var]
            del process_dict[var]
    return process_dict

class verifyCpuHog():
    def __init__(self,hdl,log,*args):
        self.result='pass'
        arggrammar={}
        arggrammar['threshold']='-type int -default 15'
        arggrammar['mode']='-type str -choices cli,linux -default linux'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.hog_list=[]
        #print(ns.mode)
        if ns.mode == 'cli':
            process_dict = processCpu(hdl,log)
        elif ns.mode == 'linux':
            process_dict = processCpufromLinux(hdl,log)
        for i in process_dict:
            var=process_dict[i]
            if float(var['sec']) >= ns.threshold:
                log.info('Found hogging processes {0}, rechecking after 10 secs'.format(var))
                time.sleep(10)
                if ns.mode == 'cli':
                    new_process_dict = processCpu(hdl,log)
                elif ns.mode == 'linux':
                    new_process_dict = processCpufromLinux(hdl,log)
                try:
                    if float(new_process_dict[i]['sec']) >= ns.threshold:
                        self.result = 'fail'
                        self.hog_list.append((i,new_process_dict[i]['sec']+'%'))
                except Exception as e:
                    self.result = 'fail'
                    self.hog_list.append((i,'Dict not updated'))
        return None

#Added by Nilesh
def verifyTelnet(dut,hlite,log):
    import icon
    dut_params=hlite.gd['inputdict']['node_dict'][dut]['params'] 
    arggrammar={}
    arggrammar['mgmt_ip_addr']='-type str -required true'
    arggrammar['user_name']='-type str -required true'
    arggrammar['password']='-type str -required true'
    arggrammar['name']='-type str -required true'
    dut_ns=parserutils_lib.argsToCommandOptions(dut_params,arggrammar,log)

    dut_hdl_param = '-ip_addr {0} -user_name {1} -password {2} -switch_name {3}'.format(dut_ns.mgmt_ip_addr,dut_ns.user_name,dut_ns.password, dut_ns.name)
    dut_hdl_telnet= icon.icontelnet(log,dut_hdl_param)
    kwargs={}
    kwargs['timeout']=2
    try:
        dut_hdl_telnet.execute('term length 0')
        retVal=dut_hdl_telnet.execute('show version',**kwargs)
    except Exception as e:
        log.error('show version took more than 2 seconds to respond')
        dut_hdl_telnet.idestroy()
        return 0
    dut_hdl_telnet.idestroy()
    if retVal == None:
        return 0 
    else:
        return 1

def checkMTS(hdl,log,*args):
    import verify_lib
    obj=verify_lib.verifyMtsBuffersUsage(hdl,log,*args)
    return obj

def verifyCpuHogging(hdl,log,*args):
    obj=verifyCpuHog(hdl,log,*args)
    return obj

def getMem(hdl,log):
    req_dict=getMemStatsDetailDict(hdl,log,'bgp')
    #print(req_dict)
    return req_dict

def incrIpAddr(addr):
    ip_reg=re.match('(\d+).(\d+).(\d+).(\d+)',addr)    
    num=int(ip_reg.group(3))
    num+=1
    new_addr=ip_reg.group(1)+'.'+ip_reg.group(2)+'.'+str(num)+'.'+ip_reg.group(4)
    return new_addr

def configurePrefixlist(hdl,log,*args):
    log.info("Now inside method configurePrefixlist")
    arggrammar={}
    arggrammar['prefixlist']='-type str -required true'
    arggrammar['permit_nw']='-type list'
    arggrammar['deny_nw']='-type list'
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if hasattr(parseoutput,'permit_nw') and parseoutput.permit_nw is not None:
        for var in parseoutput.permit_nw:
            hdl.iconfig('ip prefix-list {0} permit {1}'.format(parseoutput.prefixlist,var))
    if hasattr(parseoutput,'deny_nw') and parseoutput.deny_nw is not None:
        for var in parseoutput.deny_nw:
            hdl.iconfig('ip prefix-list {0} deny {1}'.format(parseoutput.prefixlist,var))

def configureRoutemap(hdl,log,*args):
    log.info("Now inside method configureRoutemap")
    arggrammar={}
    arggrammar['routemap']='-type str -required true'
    arggrammar['prefix_list']='-type list -required true'
    arggrammar['flag']='-type bool -default True'
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    for var in parseoutput.prefix_list:
        if parseoutput.flag:
            hdl.iconfig('route-map {0} \n match ip address prefix-list {1}'.format(parseoutput.routemap,var))
        else:
            hdl.iconfig('route-map {0} \n no match ip address prefix-list {1}'.format(parseoutput.routemap,var))

def configureV6Prefixlist(hdl,log,*args):
    log.info("Now inside method configurePrefixlist")
    arggrammar={}
    arggrammar['prefixlist']='-type str -required true'
    arggrammar['permit_nw']='-type list'
    arggrammar['deny_nw']='-type list'
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if hasattr(parseoutput,'permit_nw') and parseoutput.permit_nw is not None:
        for var in parseoutput.permit_nw:
            hdl.iconfig('ipv6 prefix-list {0} permit {1}'.format(parseoutput.prefixlist,var))
    if hasattr(parseoutput,'deny_nw') and parseoutput.deny_nw is not None:
        for var in parseoutput.deny_nw:
            hdl.iconfig('ipv6 prefix-list {0} deny {1}'.format(parseoutput.prefixlist,var))

def configureV6Routemap(hdl,log,*args):
    log.info("Now inside method configureRoutemap")
    arggrammar={}
    arggrammar['routemap']='-type str -required true'
    arggrammar['prefix_list']='-type list -required true'
    arggrammar['flag']='-type bool -default True'
    arggrammar['seq']='-type int -default 10'
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    for var in parseoutput.prefix_list:
        if parseoutput.flag:
            hdl.iconfig('route-map {0} permit {2} \n match ipv6 address prefix-list {1}'.format(parseoutput.routemap,var,parseoutput.seq))
        else:
            hdl.iconfig('route-map {0} deny {2} \n match ipv6 address prefix-list {1}'.format(parseoutput.routemap,var,parseoutput.seq))

def unconfigureV6Prefixlist(hdl,log,*args):
    log.info("Now inside method configurePrefixlist")
    arggrammar={}
    arggrammar['prefixlist']='-type str -required true'
    arggrammar['permit_nw']='-type list'
    arggrammar['deny_nw']='-type list'
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    if hasattr(parseoutput,'permit_nw') and parseoutput.permit_nw is not None:
        for var in parseoutput.permit_nw:
            hdl.iconfig('no ipv6 prefix-list {0} permit {1}'.format(parseoutput.prefixlist,var))
    if hasattr(parseoutput,'deny_nw') and parseoutput.deny_nw is not None:
        for var in parseoutput.deny_nw:
            hdl.iconfig('no ipv6 prefix-list {0} deny {1}'.format(parseoutput.prefixlist,var))

def unconfigureV6Routemap(hdl,log,*args):
    log.info("Now inside method configureRoutemap")
    arggrammar={}
    arggrammar['routemap']='-type str -required true'
    arggrammar['prefix_list']='-type list -required true'
    arggrammar['flag']='-type bool -default True'
    arggrammar['seq']='-type int -default 10'
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    for var in parseoutput.prefix_list:
        if parseoutput.flag:
            hdl.iconfig('no route-map {0} permit {1}'.format(parseoutput.routemap,parseoutput.seq))
        else:
            hdl.iconfig('no route-map {0} deny {1}'.format(parseoutput.routemap,parseoutput.seq))
 
def applyRoutemap(hdl,log,*args):
    log.info("Now inside method applyRoutemap")
    arggrammar={}
    arggrammar['as_num']='-type str -required true'
    arggrammar['nei']='-type str -required true'
    arggrammar['routemap']='-type str -required true'
    parseoutput=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    hdl.iconfig('router bgp {0} \n neighbor {1} \n address-family ipv4 unicast \n route-map {2} in'.format(parseoutput.as_num,parseoutput.nei,parseoutput.routemap))

def incrV6(v6_addr,iter,step=1):
    new_list=[]
    mt=re.match('(\d)(\d)(\d)(\d)(::\d+)',v6_addr)
    if not mt:
        return new_list
    new_list.append(v6_addr)
    num=int(mt.group(4))
    cnt=int(mt.group(3))
    tnum=mt.group(5)
    pos=3
    while len(new_list) < iter:
        if cnt == 10:
            fnum='a'
        elif cnt == 11:
            fnum='b'
        elif cnt == 12:
            fnum='c'
        elif cnt == 13:
            fnum='d'
        elif cnt == 14:
            fnum='e'
        elif cnt == 15:
            fnum='f'
        else:
            fnum=str(cnt)
        while num < 15:
            num+=step
            if num == 10:
                snum='a'
            elif num == 11:
                snum='b'
            elif num == 12:
                snum='c'
            elif num == 13:
                snum='d'
            elif num == 14:
                snum='e'
            elif num == 15:
                snum='f'
            else:
                snum=str(num)
            if pos == 3:
                new_addr=mt.group(1)+mt.group(2)+fnum+snum+tnum
            elif pos == 2:
                new_addr=mt.group(1)+fnum+mt.group(3)+snum+tnum
            elif pos == 1:
                new_addr=fnum+mt.group(2)+mt.group(3)+snum+tnum
            new_list.append(new_addr)
            if len(new_list) == iter:
                break
        num=-1
        if cnt == 15:
            if pos - 1 > 0:
                pos=pos-1
                cnt=int(mt.group(pos))
            else:
                return new_list
        else:
            cnt+=1
    return new_list

def setCoppProfile(hdl,sw_name,profile='default'):
    hdl.isendline('setup')
    hdl.iexpect('configuration dialog \(yes/no\):')
    hdl.isendline('yes')
    hdl.iexpect('\(yes/no\) \[n\]:')
    hdl.isendline('')
    hdl.iexpect('\(yes/no\) \[n\]:')
    hdl.isendline('') 
    hdl.iexpect('\(yes/no\) \[n\]:')
    hdl.isendline('') 
    hdl.iexpect('name :')
    hdl.isendline('{0}'.format(sw_name))
    hdl.iexpect('management configuration\? \(yes/no\) \[y\]:')
    hdl.isendline('no')
    hdl.iexpect('\(yes/no\) \[y\]:')
    hdl.isendline('no')
    hdl.iexpect('\(yes/no\) \[n\]:')
    hdl.isendline('yes')
    hdl.iexpect('\(yes/no\) \[y\]:')
    hdl.isendline('yes')
    hdl.iexpect('\(dsa/rsa\) :')
    hdl.isendline('rsa')
    hdl.iexpect('<768-2048> :')
    hdl.isendline('1024')
    hdl.iexpect('\(yes/no\) \[n\]:')
    hdl.isendline('') 
    hdl.iexpect('\(L3/L2\) \[L2\]:')
    hdl.isendline('') 
    hdl.iexpect('\(shut/noshut\) \[noshut\]:')
    hdl.isendline('') 
    hdl.iexpect('\( default / l2 / l3 \) \[default\]:')
    hdl.isendline('{0}'.format(profile))
    hdl.iexpect('\(yes/no\) \[n\]:')
    hdl.isendline('')
    hdl.iexpect('\(yes/no\) \[y\]:')
    hdl.isendline('yes')
    time.sleep(120)
    hdl.iexpect('\(yes/no\) \[n\]:')
    hdl.isendline('yes')
    time.sleep(10)
    hdl.iexpect('{0}'.format(sw_name))

def flapIntf(hdl,svi):
    sleep_list=[1,2,3,5,10,20]
    #print('Flapping interface vlan {0}'.format(svi))
    cfg1='''interface vlan {0}
             shut
         '''.format(svi)
    hdl.iconfig(cfg1)
    time.sleep(random.choice(sleep_list))
    cfg2='''interface vlan {0}
             no shut
         '''.format(svi)
    hdl.iconfig(cfg2)

def getSnmpOp(cmd,swIp,oid,log):
    import commands
    if cmd == 'snmpbulkget':
        cmd='{0} -v {1} -c {2} -Cr50 {3} {4}'.format(cmd,'2c','public',swIp,oid)
    else:
        cmd='{0} -v {1} -c {2} {3} {4}'.format(cmd,'2c','public',swIp,oid)
    retVal=commands.getstatusoutput(cmd)
    log.info('{0} OUTPUT BEGIN'.format(cmd))
    log.info(retVal)
    log.info('{0} OUTPUT END'.format(cmd))
    return retVal

def getRunasDict(runcfg):
    retVal={}
    num=0
    runcfg=runcfg.strip()
    for i in runcfg.split('\n'):
        retVal.update({num: i})
        num+=1
    return retVal

class DictDiffer(object):
    def __init__(self, current_dict, past_dict):
        self.current_dict, self.past_dict = current_dict, past_dict
        self.set_current, self.set_past = set(current_dict.keys()), set(past_dict.keys())
        self.intersect = self.set_current.intersection(self.set_past)
    def added(self):
        return self.set_current - self.intersect
    def removed(self):
        return self.set_past - self.intersect
    def changed(self):
        return set(o for o in self.intersect if self.past_dict[o] != self.current_dict[o])
    def unchanged(self):
        return set(o for o in self.intersect if self.past_dict[o] == self.current_dict[o])


def disruptSwitch(log,hlite,*args):
    import icon
    arggrammar={}
    arggrammar['dut']='-type str -required true'
    arggrammar['action']='-type str -required true -choices reload,powercycle'
    arggrammar['write_erase']='-type bool -default False'
    arggrammar['copy_flag']='-type bool -default True'
    options_args=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

    node_params=hlite.gd['inputdict']['node_dict'][options_args.dut]['params']
    hdl=hlite.gd['connectObj'].switch_con_hdl_dict[options_args.dut]
    ssh_hdl=hlite.gd['connectObj'].switch_hdl_dict[options_args.dut]
    arggrammar={}
    arggrammar['mgmt_ip_addr']='-type str -required True'
    arggrammar['mgmt_prf_len']='-type str -required True'
    arggrammar['user_name']='-type str -default admin'
    arggrammar['password']='-type str -default insieme'
    arggrammar['device_type']='-type str -format {0} -default NA'.format(rex.DEVICE_TYPE)
    arggrammar['flags']=['ignore_unknown_key']
    options_namespace=parserutils_lib.argsToCommandOptions(node_params,arggrammar,log,'namespace')

    iconssh_params='-ip_addr {0} -user_name {1} -password {2} -device_type {3}'\
    .format(options_namespace.mgmt_ip_addr,options_namespace.user_name,\
    options_namespace.password,options_namespace.device_type)
    #TBD
    #iconsshv6_params='-ip_addr {0} -user_name {1} -password {2} -device_type {3}'\
    #.format(options_namespace.mgmt_ip_addr,options_namespace.user_name,\
    #options_namespace.password,options_namespace.device_type)
    #### Adding the same for GMR1 due to Copy r s issue###########
    kwargs={}
    kwargs['timeout']=180
    if options_args.copy_flag:
        ssh_hdl.execute('copy run start',**kwargs)

    out=1
    if options_args.action == "reload":
        try:
            #print(options_args.write_erase)
            if options_args.write_erase:
            #    hdl.execute('copy running-config bootflash:temp.cfg')
                out=hdl.reloadSwitch('-write_erase {0}'.format(options_args.write_erase))
            else:
                out=hdl.reloadSwitch()
        except Exception as e:
            log.error('Error occured while trying reload of switch'+str(e))
            return 0
    elif options_args.action == "powercycle":
        try:
            if options_args.write_erase:
                out=hdl.powerCycleSwitch('-write_erase {0}'.format(options_args.write_erase))
            else:
                out=hdl.powerCycleSwitch()
        except Exception as e:
            log.error('Error occured while trying power cycle of switch'+str(e))
            return 0
    return out
###################

def snmpIfIndexDict(hdl,log):
    show_snmp_ifindex = hdl.execute('show interface snmp-ifindex')
    exp = '(\S+)\s+(\d+)'
    ifindex_list = re.findall(exp,show_snmp_ifindex,re.I|re.M)
    ifindex_dict = convertListToDict(ifindex_list,['interface','ifindex'],'interface')
    return ifindex_dict

def getServerTimestamp(srv_hdl,log):
    log.info('Executing date command on server')
    srv_hdl.sendline("date")
    srv_hdl.expect('\[.*#')
    ls_var = srv_hdl.before
    log.info('Date on server is {0}'.format(ls_var))

    pat = '\S+\s(\S+)\s+(\d+)\s(\S+)\s\S+\s(\d+)'
    out1 = re.findall(pat, ls_var)
    if not out1:
        testResult('fail', 'Failed to execute date command on server',log)
        return
    out = out1[0]
    ser_yr = int(out[len(out)-1])
    ser_mon = time.strptime(out[0],'%b').tm_mon
    ser_day = int(out[1])
    ser_time = out[2].split(":")
    ser_hr = int(ser_time[0])
    ser_min = int(ser_time[1])
    ser_sec = int(ser_time[2])
    server_time = [ser_yr,ser_mon,ser_day,ser_hr,ser_min,ser_sec]
    log.info('returned server timestamp is {0}'.format(server_time))
    return server_time

def getEnvPS(hdl,log):
    #print('Fetch the Enviornment info')
    show_env = hdl.execute('show environment')
    #show_env = show_env.split('\n')
    #allmatch = {}
    #for env in show_env:
    #pattern_n9k = "([0-9])\s+(N9K-PAC-3000W-B)\s+(\S+.W)\s+(\S+.W)\s+(\S+.W)\s+(\S+)"
    pattern_n3k = "(PS-.)\s+(\S+)\s+(\S+)\s+(ok)"
    #pattern = "(\S+)\s+(\S+)"
        #for env in show_env:
    match_list=re.findall( pattern_n3k, show_env)
    log.info('the match_list is {0}'.format(match_list))

    psu = []
    for match in match_list:
        env_dict=convertListToDict(match,['Mod', 'Model', 'HW', 'Status'])
        log.debug("the value of env is " + str(env_dict))
        psu.append(env_dict)
    log.info('the value of env is ' + str(psu))
    return psu

def getEnvFan(hdl,log):
    #print('Fetch the Enviornment info')
    show_env = hdl.execute('show environment')
    #show_env = show_env.split('\n')
    #allmatch = {}
    #for env in show_env:
    #pattern_n9k = "([0-9])\s+(N9K-PAC-3000W-B)\s+(\S+.W)\s+(\S+.W)\s+(\S+.W)\s+(\S+)"
    pattern_n3k = "(Fan-.)\s+(\S+)\s+(\S+)\s+(ok)"
    #pattern = "(\S+)\s+(\S+)"
        #for env in show_env:
    match_list=re.findall( pattern_n3k, show_env)
    log.info('the match_list is {0}'.format(match_list))

    fan = []
    for match in match_list:
        env_dict=convertListToDict(match,['Mod', 'Model', 'HW', 'Status'])
        log.debug("the value of env is " + str(env_dict))
        fan.append(env_dict)
    log.info('the value of env is ' + str(fan))
    return fan

def getTransceiverInfo(hdl,log,interface):

    showoutput = hdl.execute ("show interface {0} transceiver details".format(interface))

    pattern_sfp='transceiver is (\S+)'
    pattern_type='type is (\S+)'
    pattern_name='name is (\S+)'
    pattern_partno='part number is (\S+)'
    type=re.findall(pattern_type, showoutput)
    return type.pop(0)


def getInterfaceCounterBrief (hdl, log, intf):
    show_int="show interface {0} counters brief".format(intf)
    output=hdl.execute(show_int)

    pat='(\S+)\s+[0-9.]+\s+([0-9]+)\s+[0-9.]+\s+([0-9]+)\s+\d+'
    pktRate=re.findall( pat, output, re.I|re.M)
    pktRateDict = convertListToDict(pktRate, ['Interface','InputFrames', 'OutputFrames'],'Interface')
    return pktRateDict


def getIpPimGroupRange(hdl,log):
    showoutput = hdl.execute('show ip pim group-range')
    exp = '({0}\/\d+).*\s+([ASM]+)\s+(\S+)'.format(rex.IPv4_ADDR)
    ipPim_list = re.findall(exp,showoutput,re.I|re.M)
    ipPim_dict = convertListToDict(ipPim_list,['GroupRange','Mode','rp-address'],'GroupRange')
    return ipPim_dict

def get_configured_ospf_proc_id (switch_conn_hdl, log):
    '''
     This will get ospf process id configured on switch
     return None if its not configured
     return process id if it has been configured
     '''

    output_buff = switch_conn_hdl.execute('show run ospf | no-more')
    all_lines = output_buff.split('\n')
    for line in all_lines:
       match = re.search(r'router ospf (.*)', line)
       if match:
          return match.group(1)
    return "None"

def get_configured_bgp_as_nu(switch_conn_hdl, log):
    '''
     This will get bgp AS number configured on switch
     return 0 if its not configured
     return AS_nu if it has been configured
     '''

    output_buff = switch_conn_hdl.execute('show run bgp | no-more')
    all_lines = output_buff.split('\n')
    for line in all_lines:
       match = re.search(r'router bgp (.*)', line)
       if match:
          return match.group(1)
    return 0

def clean_switch_config(hdl, log):
    '''
     This will clear config on switch
     1. makes all interfaces default
     2. deletes SVI if it has been configured
     3. deletes Port-channels if they have been configured
     4. deletes Loopback interfaces
     5. Deletes Tunnel interfaces
     6. makes no router bgp AS-Nu if configured
     7. Removes all prefix-list|route-map|community-list
     8. Removes OSPF config
     9. Removes all Vlans configured
     10. Removes all monitor sessions configured
    '''
    intf_dict = getInterfaceBriefDict(hdl, log)
    hdl.execute('configure')
    for intf in intf_dict.keys():
       if re.search(r'Eth', intf):
          hdl.execute('default interface ' + intf)

    for intf in intf_dict.keys():
       if re.search(r'Vlan|Po|Lo|Tu', intf):
          hdl.execute('no interface ' + intf)
    output_buff = hdl.iconfig('interface vlan 1' + '\n' + 'no ip address' + '\n' + 'no ipv6 address')

    bgp_as_nu = get_configured_bgp_as_nu(hdl, log)
    if bgp_as_nu:
       hdl.iconfig('no router bgp ' + bgp_as_nu)

    ospf_proc_id = get_configured_ospf_proc_id(hdl, log)
    match = re.search(r'None', ospf_proc_id)
    if match is None:
       hdl.iconfig('no router ospf ' + ospf_proc_id)

    output_buff = hdl.execute('show running-config rpm')
    all_lines = output_buff.split('\n')
    for line in all_lines:
       if re.search(r'prefix-list|route-map|community-list', line):
          if re.search(r'match\s|set\s', line):
             continue
          hdl.iconfig('no ' + line)

    output_buff = hdl.execute('show running-config | i \"vlan 1\"')
    all_lines = output_buff.split('\n')
    for line in all_lines:
       if re.search(r'^vlan 1', line):
          hdl.iconfig('no ' + line)
          break

    hdl.iconfig('no monitor session all')

def shutUnshutAllInterfaces(hdl,oper,log=None):
    out=hdl.execute('show interface brief')
    for line in out.split('\n'):
        match=re.search('^(Eth[^ \t]+)',line)
        if match:
            if match.group(1)=='Ethernet':
                continue
            if oper=="shut":
                msdc_common_lib.shutInterface(hdl,match.group(1),log)
            elif oper=="no shut":
                msdc_common_lib.noshutInterface(hdl,match.group(1),log)

def unshutAllInterfaces(hdl,log=None):
    shutUnshutAllInterfaces(hdl,"no shut",log)

'''
def shutAllInterfaces(hdl,log=None):
    shutUnshutAllInterfaces(hdl,"shut",log)
'''

#######
# Procedure to return the front portMode configured in the box
#######
def getFrontPortMode(hdl):
        '''
        1. Get the front port mode configured in the box.
        '''
        # Get the front portmode configured in this platform
        out=hdl.execute('show run | grep "front portmode"')
        frontPortMode=None
        for line in out.split('\n'):
                match=re.search('front portmode ([^\r\n \t]+)',line)
                if match:
                        frontPortMode=match.group(1)
                        break

        return frontPortMode

#######
# Procedure to return the portMode and tuple mode configured in the box
#######
def getPortMode(hdl):
        '''
        1. Get the port mode and tuple mode configured in the box.
        '''
        # Get the portmode configured in this platform
        out=hdl.execute('show run | grep "profile portmode"')
        portMode=None
        tupMode=None
        for line in out.split('\n'):
                match=re.search('profile portmode ([^\r\n \t]+)[ \t]*([^\r\n \t]*)',line)
                if match:
                        portMode=match.group(1)
                        tupMode=match.group(2)
                        break
        
        return (portMode,tupMode)

########
# Required:
#       switch_hdl_dict : Switch handle
#       front_port_mode : Needs to be defined in topology file under 'dut' dict
########

def configureFrontPortMode(hlite,node,switch_hdl_dict,log):
        '''
        1. Check the front port mode configured in the switch
        2. Compare it with the front port mode configured in the topology file
        3. Set the front port mode to the one set in the topology file
        4. Check the configuration applied successfully
        '''

        hdl=switch_hdl_dict[node]

        # Get the front portMode configured for this platform
        frontPortMode=getFrontPortMode(hdl)
        if frontPortMode == None:
            # Front port mode is not applicable to this platform
            return 1

        topo_config_dict=hlite.gd['inputdict']['Topology']['dut']
        if 'front_port_mode' in topo_config_dict[node].keys():
                frontPortModeCfgFile=topo_config_dict[node]['front_port_mode']
        else:
                log.info("Front Port mode not defined in topology file")
                return 1

        if frontPortModeCfgFile=='NA':
                log.info("Front Port mode is NA in topology file")
                return 1

        result=1
        if not frontPortMode==frontPortModeCfgFile:
                # Set the hadware profile front port mode
                hdl.execute('conf')
                out=hdl.execute('hardware profile front portmode {0}'.format(frontPortModeCfgFile))
                if re.search('Invalid|Error',out,re.I):
                        log.error("Unable to configure front portmode for switch {0}".format(hdl.switchName))
                        return 0
                
                finalFrontPortMode=getFrontPortMode(hdl)
                
                # Check the front portmode configured 
                
                if not finalFrontPortMode==frontPortModeCfgFile:
                        log.error("Front Port mode configured is not set as expected")
                        result=0
        
        if result:
                return 1 
        else:
                return 0

        
########
# Required:
#        switch_con_hdl_dict : Need console handle to do switch reload if profile port mode is changed
#        port_mode : Needs to be defined in topology file under 'dut' dict
#
# Optional:
#        tup_mode : Define tuple mode in topology file under 'dut' dict
########
def configurePortMode(hlite,node,switch_con_hdl_dict,log):
        '''
        1. Check the port mode and tup mode configured in the switch
        2. Compare it with the port mode and tup mode configured in the topology file
        3. Set the port mode to the one set in the topology file and reload the box
        4. Check the configuration applied successfully
        '''
        # Make sure console login handle is available for this testcase
        try :
                l_keys=switch_con_hdl_dict.keys()
                #If node not present in the key elements of console dict, return from exception block
                l_keys.index(node)
        except ValueError:
                log.error("No console handle defined for node {0}. It is required for DUT".format(node))
                return 0
        
        hdl=switch_con_hdl_dict[node]
        
        # Get the portMode and tupMode configured for this platform
        portMode,tupMode=getPortMode(hdl)
        
        rel_flag = 0
        
        topo_config_dict=hlite.gd['inputdict']['Topology']['dut']
        if 'port_mode' in topo_config_dict[node].keys():
                portModeCfgFile=topo_config_dict[node]['port_mode']
        else:
                log.error("Port mode not defined in topology file")
                return 0

        if 'tup_mode' in topo_config_dict[node].keys():
                tupModeCfgFile=topo_config_dict[node]['tup_mode']
        else:
                tupModeCfgFile=''        

        result1=1
        if not portMode==portModeCfgFile or not tupMode==tupModeCfgFile:
                # Set the hadware profile port mode
                hdl.execute('conf')
                out=hdl.execute('hardware profile portmode {0} {1}'.format(portModeCfgFile,tupModeCfgFile))
                if re.search('Invalid|Error',out,re.I):
                        log.error("Unable to configure portmode for switch {0}".format(hdl.switchName))
                        return 0
                # Copy r s; reload
                l_args='-dut {0} -write_erase {1} -action {2}'.format(node,'False', 'reload')
                disruptSwitch(log, hlite, l_args )
                # Set the rel_flag to connect to mgmt hdl
                rel_flag=1
                
                finalPortMode,finalTupMode=getPortMode(hdl)
                
                # Check the portmode and tup mode configured after copy r s; rel
                
                if not finalPortMode==portModeCfgFile or not finalTupMode==tupModeCfgFile:
                        log.error("Port mode and/or tup mode configured after copy r s ; rel is not set as expected")
                        result1=0
        
        result2=True
        if rel_flag==1:
                sw_hdl=hlite.gd['connectObj'].switch_hdl_dict[node]
                # Reconnect to switch mgmt handle after reload
                result2 = sw_hdl.issh()
                if not result2:
                        log.error("Unable to reconnect the switch management handle after reload")
        
        if result1 and result2:
                return 1 
        else:
                return 0

########
# Required:
#        switch_con_hdl_dict : Need console handle to do switch reload if profile port mode is changed
#        
# Optional:
#        breakIn : Set this optional argument to True if the need is to break-in the ports as well after configure default port mode
########
def configureDefaultPortMode(hlite,node,switch_con_hdl_dict,log,breakIn=True):
        '''
        1. Check the port mode and tup mode configured for the switch
        2. Compare it with default port mode and tup mode for the platform.
        3. Set the port mode and reload the switch
        4. Check the configuration applied successfully after reload
        5. Optionally, if breakIn is set, break-in all the dynamic ports that supports dynamic break-out
        '''
        
        # Make sure console login handle is available for this testcase
        try :
                l_keys=switch_con_hdl_dict.keys()
                #If node not present in the key elements of console dict, return from exception block
                l_keys.index(node)
        except ValueError:
                log.error("No console handle defined for node {0}. It is required for DUT".format(node))
                return 0
        
        hdl=switch_con_hdl_dict[node]
        out=hdl.execute("show module")
        flag=0
        for line in out.split('\n'):
          match=re.search("[Ss]uper[^ \t]+[ \t]+([^ \t]+)",line)
          if match :
                model=match.group(1)
                flag=1
                break

        if flag == 0 :
                log.error("Unable to get the model for the switch {0}".format(hdl.switchName))
                return 0

        # Get the portMode and tupMode configured for this platform
        portMode,tupMode=getPortMode(hdl)
        
        rel_flag = 0
        
        if re.search("3064",model):
                defPortMode="64x10G"
        elif re.search("3016",model):
                defPortMode="16x40G"
        elif re.search("3172",model):
                defPortMode="48x10G+breakout6x40G"
        elif re.search("3132",model):
                defPortMode="32x40G"
        else:
                log.error("In configureDefaultPortMode:Currently the function defintion is not supported for model {0}".format(model))
                return 0
        
        result3=1
        # Reload the box if default portmode is not configured correctly
        if not portMode==defPortMode or not tupMode:
                hdl.iconfig('no hardware profile portmode')
                # Copy r s; reload
                l_args='-dut {0} -write_erase {1} -action {2}'.format(node,'False', 'reload')
                disruptSwitch(log, hlite, l_args )
                # Set the rel_flag to connect to mgmt hdl
                rel_flag=1
        
                finalPortMode,finalTupMode=getPortMode(hdl)
                
                # Check the portmode and tup mode configured after copy r s; rel
                
                if not finalPortMode==defPortMode or finalTupMode:
                        log.error("Port mode and/or tup mode configured after copy r s ; rel is not set as expected")
                        result3=0
        
        result1=1
        
        # After configuring default portMode, check if we want to break-in dynamic ports
        if breakIn:
                lo_limit=0
                up_limit=0
                if re.search("3172",model):
                        lo_limit=49
                        up_limit=54
                        speed=40000
                        
                elif re.search("3132",model):
                        lo_limit=1
                        up_limit=24
                        speed=40000
                                        
                # If the ports are configured in breakout mode, break-in them
                out=hdl.execute('show int br')
                for line in out.split('\n'):
                    match=re.search('(^Eth[0-9]+/([0-9]+)/1)',line)
                    if match and int(match.group(2))>=lo_limit and int(match.group(2))<=up_limit:
                        #print "Interface {0} configured in breakout port mode".format(match.group(1))
                        cfg=     '''interface {0}
                                    speed {1}
                                    '''.format(match.group(1),speed)
                        out=hdl.iconfig(cfg)
                        if re.search('Error|Invalid',out,re.I):
                                result1=0
        
                if not result1:
                        log.error("Unable to break-in the ports")
        
        result2=1
        if rel_flag:
                sw_hdl=hlite.gd['connectObj'].switch_hdl_dict[node]
                # Reconnect to switch mgmt handle after reload
                result2 = sw_hdl.issh()
                if not result2:
                        log.error("Unable to reconnect the switch management handle after reload")
        
        if not result1 or not result2 or not result3:
                return 0
        else:
                return 1


#======================================================================================#
# configUnconfigAlpmMode:
#    Method to config/unconfig Alpm Mode
#======================================================================================#

def configUnconfigAlpmMode(self, hlite, node, operation):

    hdl=self.switch_hdl_dict[node]
    mod_list = ['N3K-C3132Q-40GE-SUP','N3K-C3172PQ-10GE-SU']
    mod_dict = getLineCardDict(hdl,self.log)
    self.log.info('Platforms are {0}'.format(mod_dict))
    if mod_dict['1']['Model'] not in mod_list:
      self.log.info('ALPM mode is not supported on {0}'.format(hdl.switchName))
      return 1
    else:
      self.log.info('ALPM mode is supported on {0}'.format(hdl.switchName))

    self.log.info('{0} the switch {1} ALPM mode'.format(operation,hdl))

    output1 = hdl.execute("show running-config | i \'system routing max-mode l3\'")
    match1 = re.search(r'system routing max-mode l3',output1)
    self.log.info('Match1: {0}'.format(match1))

    output2 = hdl.execute("show hardware profile status | i ALPM")
    match2 = re.search(r'Unicast LPM Table is in ALPM mode shared b/n v4 & v6...',output2)
    self.log.info('Match2: {0}'.format(match2))

    if operation == 'config':
      if (match1 != None) or (match2 != None):
        self.log.error('ALPM mode is already enabled on the switch {0} to be configured'.format(hdl.switchName))
        return 0
      else:
        cfg = 'system routing max-mode l3'

    if operation == 'unconfig':
      if (match1 == None) or (match2 == None):
        self.log.error('TEST FAILED. ALPM mode is not enabled on the switch {0} to be unconfigured'.format(hdl.switchName))
        return 0
      else:
        cfg = 'no system routing max-mode l3'

    hdl.iconfig(cfg)

    try:
      if not disruptSwitch(self.log, hlite,'-dut {0} -action {1}'.format(node,'reload')):
        self.log.error('Error occured while trying reload of Switch {0} after ALPM mode {1}'.format(hdl.switchName, operation))
        return
    except Exception as e:
      self.log.error('Error occured while trying reload of Switch {0} after ALPM mode {1}'.format(e,operation))
      err_msg='Error occured while trying reload of Switch {0} after ALPM mode {1}'.format(e,operation)
      testResult( 'fail', err_msg, self.log )
      return

    hdl=self.switch_hdl_dict[node]
    output1 = hdl.execute("show running-config | i \'system routing max-mode l3\'")
    match1 = re.search(r'system routing max-mode l3',output1)
    self.log.info('Match1: {0}'.format(match1))

    output2 = hdl.execute("show hardware profile status | i ALPM")
    match2 = re.search(r'Unicast LPM Table is in ALPM mode shared b/n v4 & v6...',output2)
    self.log.info('Match2: {0}'.format(match2))

    if operation == 'config':
      if (match1 == None) or (match2 == None):
        self.log.error('TEST FAILED. ALPM mode is not getting configured on the switch {0}'.format(hdl.switchName))
        return 0

    if operation == 'unconfig':
      if (match1 != None) or (match2 != None):
        self.log.error('TEST FAILED. ALPM mode is not getting unconfigured on the switch {0}'.format(hdl.switchName))
        return 0

    return 1


### Modified shutAllInterfaces to set the interfaces in range

def unshutAllInterfaces(hdl):
    out=hdl.execute('show interface brief | grep Eth')
    int_list=getIntfList(out)
    intfs=",".join(str(e) for e in int_list)
    hdl.execute("config ter")
    hdl.execute("interface {0}".format(intfs))
    hdl.execute("no shut")


def shutAllInterfaces(hdl):
    out=hdl.execute('show interface brief | grep Eth')
    int_list=getIntfList(out)
    intfs=",".join(str(e) for e in int_list)
    hdl.execute("config ter")
    hdl.execute("interface {0}".format(intfs))
    hdl.execute("shut")

def getIntfList(out):
    ''' this function will return the interfaces in list with range'''
    int_list=[]
    is3tuple=0
    for line in out.split('\n'):
        match=re.search('^(Eth[^ \t]+)',line)
        if match:
            if match.group(1)=='Ethernet':
                continue
            intf=match.group(1)
            int3tuple=re.search(r'([1-9]\/[\d]+\/[\d]+)',intf)
            if int3tuple:
                is3tuple+=1
                if is3tuple==1:
                    int3tuple_intf=match.group(1)+"-4"
                    int_list.append(int3tuple_intf)
                if is3tuple==4:
                   is3tuple=0
                continue
            int_list.append(match.group(1))
    return int_list

def getIntfMac(hdl,intf):
        out=hdl.execute('show interface {0}'.format(intf))
        pattern='[a-f|0-9]+\.[a-f|0-9]+\.[a-f|0-9]+'
        return re.search(pattern,out).group()

