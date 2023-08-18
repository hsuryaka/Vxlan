import os
import sys
import argparse
import yaml
import os
import sys
import re
import random
import time
import logging
import collections
import inspect
from common_lib import parserutils_lib
import threading
from common_lib import verify_lib
from common_lib import utils

class configHashOffset(object):
     """
     Class to configure hash-offset with or w/o concatenation based on the hash_offset_config_dict dictionary
     hash_offset_config_dict looks like below:
     hash_offset_config_dict:
      node01:
           case1: -offset_value 10 -concatenation False -negative_tc False
           case2: -offset_value 1 -concatenation False -negative_tc False
           case3: -offset_value 15 -concatenation False -negative_tc False
           case4: -offset_value 16 -concatenation False -negative_tc True
           case5: -offset_value 0 -concatenation False -negative_tc False
           case6: -offset_value 63 -concatenation False -negative_tc True
           case6: -offset_value 64 -concatenation False -negative_tc True
           case7: -offset_value 3 -concatenation True -negative_tc False
           case8: -offset_value 0 -concatenation True -negative_tc False
           case9: -offset_value 63 -concatenation True -negative_tc False

     """

     def __init__(self,switch_hdl_dict,hash_offset_config_dict,log,*args):
        self.result='pass'
        self.log = log
        if type(hash_offset_config_dict) != dict:
             testResult ('fail', 'hash_offset_config_dict is not in dictionary format',self.log)
             self.result = 'fail'
             return
        else:
             self.hash_offset_config=hash_offset_config_dict
        if type(switch_hdl_dict) != dict:
             testResult ('fail', 'switch Handles and Names not in dictionary format',self.log)
             self.result = 'fail'
             return
        else:
             self.hdl=switch_hdl_dict
             return

        self.hash_config_nodes = []
        for node in self.hash_offset_config.keys():
             self.hash_config_nodes.append(node)

     def configVerifyOffset(self,node,args):
         """Method to configure hash-offset with or w/o concatenation and verify the same"""
         arggrammar = {}
         arggrammar['offset_value'] = '-type str -format {0} -required True'.format(rex.NUM)
         arggrammar['concatenation'] = '-type bool -default False'
         arggrammar['negative_tc'] = '-type bool -default False'
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)

         self.log.debug('Offset Value:{0};Concatenation flag:{1};Negative_Flag:{2}'.format(parse.offset_value,parse.concatenation,parse.negative_tc))

         if parse.concatenation:
                cmd='hardware ecmp hash-offset {0} concatenation'.format(parse.offset_value)
         else:
                cmd='hardware ecmp hash-offset {0}'.format(parse.offset_value)
        
         verify_run_cmd='sh run | inc offset'
         verify_run_all_cmd='sh run all | inc offset'
         verify_hw_cmd='run bash bcm-sdk-shell d chg RTAG7_PORT_BASED_HASH 361'

         self.hdl[node].iexec('config t')

         # Now execute the command and verify the output based on negative/positive test case
         if parse.negative_tc:
             if int(parse.offset_value) < 0 or int(parse.offset_value) > 63:
                # CLI should throw invalid range error
                cmd_out=self.hdl[node].iexec(cmd)
                match=re.search('Invalid',cmd_out,re.I)
                if match :
                    self.log.debug('Negative test case passed and got error as expected : $cmd_out')
                else :
                    # We are expecting invalid error after executing a negative testcase;report failure
                    self.log.error('Did not get any (Invalid)error after executing a negative tc command : {0}. Error : {1}'.format(cmd,cmd_out))
                    self.result='fail'
                    return
             else:
                if int(parse.offset_value) > 15 and parse.concatenation == False:
                    cmd_out=self.hdl[node].iexec(cmd)
                    match=re.search('ERROR',cmd_out,re.I)
                    if match :
                        self.log.debug('Negative test case passed and got error as expected : $cmd_out')
                    else :
                        # We are expecting invalid error after executing a negative testcase;report failure
                        self.log.error('Did not get any error after executing a negative tc command : {0}. Error : {1}'.format(cmd,cmd_out))
                        self.result='fail'
                else:
                    #Invalid input for a negative test case
                    self.log.error('Invalid input for a negative testcase : {0}. Check your input and run again'.format(args))
                    self.result='fail'
                    return
         else:
             if int(parse.offset_value) < 0 or int(parse.offset_value) > 63:
                #It is a incorrect input for positive case
                self.log.error('Incorrect offset range specified for positive test case. Need to be between 0 to 63')
                self.result='fail'
                return
             else:
                if parse.concatenation == False and int(parse.offset_value) > 15:
                    #It is a positive case; incorrect input
                    self.log.error('Without concatenation, allowed offset range is between 0 to 15')
                    self.result='fail'
                    return
                else:
                    #Execute the command
                    cmd_out=self.hdl[node].iexec(cmd)
                    match=re.search('Invalid|ERROR',cmd_out,re.I)
                    if match:
                        # We are not expecting any error after executing a positive testcase;report failure
                        self.log.error('Got some error after executing a positive tc command : {0}. Error : {1}'.format(cmd,cmd_out))
                        self.result='fail'
                        return
                    if parse.concatenation == False:
                        if int(parse.offset_value)==0:
                              cmd_out=self.hdl[node].iexec(verify_run_all_cmd)
                        else :
                              cmd_out=self.hdl[node].iexec(verify_run_cmd)
                        match=re.search('hardware ecmp hash-offset ([0-9]+)',cmd_out,re.I)
                        if match:
                            if int(match.group(1))==int(parse.offset_value):
                                self.log.debug('CLI Verification passed')
                            else:
                                # Offset value mismatch
                                self.log.error('Offset value in cli : \"{1}\" did not match from cli command : {0}'.format(cmd_out,match.group(1)))
                                self.result='fail'
                                return
                        else:
                            #Failed to match;report error
                            self.log.error('Failed to set in CLI - {0}'.format(cmd_out))
                            self.result='fail'
                            return
                        #Expect different fields to be set in hardware register
                        cmd_out=self.hdl[node].iexec(verify_hw_cmd)
                        if int(parse.offset_value)==0:
                            match=re.search('SUB_SEL_ECMP=1,',cmd_out,re.I)
                        else:
                            match=re.search('SUB_SEL_ECMP=1,.+,OFFSET_ECMP=([^,]+)',cmd_out,re.I)
                        if match :
                            if int(parse.offset_value)==0:
                                self.log.debug('HW Verification passed')
                            else:
                                hex=str(match.group(1))
                                offset_val=int(hex,16)
                                if offset_val==int(parse.offset_value):
                                    self.log.debug('HW Verification passed')
                                else :
                                    # Offset value mismatch in hardware
                                    self.log.error('Offset value set in hardware : \"{1}\" did not match from cli command : {0}'.format(cmd_out,match.group(1)))
                                    self.result='fail'
                                    return
                        else :
                            #Failed to match values in hardware
                            self.log.error('Failed to match config in hardware register - {0}'.format(cmd_out))
                            self.result='fail'
                            return
                    else:
                        #Run CLI command to verify
                        cmd_out=self.hdl[node].iexec(verify_run_cmd)
                        match=re.search('hardware ecmp hash-offset ([0-9]+) concatenation',cmd_out,re.I)
                        if match:
                            if int(match.group(1))==int(parse.offset_value):
                                self.log.debug('CLI Verification passed')
                            else:
                                # Offset value mismatch
                                self.log.error('Offset value in cli : \"{1}\" did not match from cli command : {0}'.format(cmd_out,match.group(1)))
                                self.result='fail'
                                return
                        else:
                            #Failed to match;report error
                            self.log.error('Failed to set in CLI - {0}'.format(cmd_out))
                            self.result='fail'
                            return
                        #Expect different fields to be set
                        cmd_out=self.hdl[node].iexec(verify_hw_cmd)
                        if int(parse.offset_value)==0:
                            match=re.search('CONCATENATE_HASH_FIELDS_ECMP=1,',cmd_out,re.I)
                        else:
                            match=re.search('OFFSET_ECMP=([^,]+),.+,CONCATENATE_HASH_FIELDS_ECMP=1',cmd_out,re.I)
                        if match :
                            if int(parse.offset_value)==0:
                                self.log.debug('HW Verification passed')
                            else:
                                hex=str(match.group(1))
                                offset_val=int(hex,16)
                                if offset_val==int(parse.offset_value):
                                    self.log.debug('HW Verification passed')
                                else :
                                    # Offset value mismatch in hardware
                                    self.log.error('Offset value set in hardware : \"{1}\" did not match from cli command : {0}'.format(cmd_out,match.group(1)))
                                    self.result='fail'
                                    return
                        else :
                            #Failed to match values in hardware
                            self.log.error('Failed to match config in hardware register - {0}'.format(cmd_out))
                            self.result='fail'
                            return


#==================================================================================#
# connectToNodes - Class to connect to all switch nodes in node_dict
#==================================================================================#

class connectToNodes(object):

    def __init__(self, log, node_dict, mgmt_dict={}, skip_console_connect='NO' ):

        import re
        import icon

        log.info('Inside connectToNodes init')

        try:
             list_of_nodes=node_dict.keys()
        except KeyError:
             #print('node dictionary in input file not defined properly ..                          \
             #     does not have any keys ..')
             failProc('node dict not properly defined')

        self.global_skip_console_connect=skip_console_connect

        self.switch_dict={}
        self.switch_hdl_dict={}
        self.switch_hdl_ipv6_dict={}
        self.switch_con_hdl_dict={}
        arggrammar={}
        arggrammar['type']='-type str -choices ["switch","router","ixia"] -default switch'
        arggrammar['model']='-type str -default nexus'
        arggrammar['name']='-type str -required True'
        arggrammar['mgmt_ip_addr']='-type str -required True'
        arggrammar['mgmt_prf_len']='-type str -required True'
        arggrammar['mgmt_ipv6_addr']='-type str -required True'
        arggrammar['mgmt_prf_len_ipv6']='-type str -required True'
        arggrammar['gateway_addr']='-type str -required True'
        arggrammar['ipv6_gateway_addr']='-type str -required True'
        arggrammar['sw_version']='-type str -default nxos1.0'
        arggrammar['vdc_name']='-type str -default NA'
        arggrammar['skip_console_connect']='-type bool'
        arggrammar['sup1_con_ipaddr']='-type str -default NA'
        arggrammar['sup1_con_port']='-type str -default NA'
        arggrammar['sup2_con_ipaddr']='-type str -default NA'
        arggrammar['sup2_con_port']='-type str -default NA'
        arggrammar['user_name']='-type str -default admin'
        arggrammar['password']='-type str -default insieme'
        arggrammar['kickstart_image_uri']='-type str -default NA'
        arggrammar['system_image_uri']='-type str -default NA'
        arggrammar['single_image_uri']='-type str -default NA'
        arggrammar['device_type']='-type str -format {0} -default NA'.format(rex.DEVICE_TYPE)
        arggrammar['module_type']='-type str -default sup'
        arggrammar['pdu_list']='-type list -default []' #Format: [('172.23.40.209',9),('172.23.40.209',10),('172.23.40.243',9]
        arggrammar['pwr_cycle']='-type bool -default False'
        arggrammar['clear_console']='-type bool -default False'
        arggrammar['sup2_boot_mode']='-type str -choices ["eobc","uri"] -default uri'
        self.sys_exit_Flag = {}
        self.node_dict={}
        connection_thread = []
        for node in node_dict:
             #print(node)
             self.sys_exit_Flag[node] = False
             n_cfg=parserutils_lib.argsToCommandOptions(node_dict[node],arggrammar,log,'namespace')
             self.node_dict[node]=n_cfg
             connections  = threading.Thread(target=self.makeConnection,args=(n_cfg,mgmt_dict,node,log))
             connection_thread.append(connections)

        for connection in connection_thread:
                connection.start()
        for connection in connection_thread:
                connection.join()
        failure_msg = ''
        for node in self.sys_exit_Flag.keys():
            if self.sys_exit_Flag[node]:
                failure_msg = failure_msg + ' {0}: '.format(node) + self.error_msg[node] + '\n'
                #print("Could not connect to Node: {0}".format(node))
        if failure_msg != '':
           sys.exit(failure_msg)
        #print(self.switch_dict)
        log.info(self.switch_dict)
        #print(self.switch_hdl_dict)
        log.info(self.switch_hdl_dict)
        #print(self.switch_hdl_ipv6_dict)
        log.info(self.switch_hdl_ipv6_dict)
        if not re.search( 'YES', skip_console_connect, re.I ):
           #print(self.switch_con_hdl_dict)
           log.info(self.switch_con_hdl_dict)

    def makeConnection (self,n_cfg,mgmt_dict,node,log):
             #print('%%% node %%%', node )
             if not n_cfg.VALIDARGS:
                 log.error('Invalid arguments to connectToNodes')
                 testResult( 'fail', 'Invalid arguments to connectToNodes', log )
                 #sys.exit(1)

             if n_cfg.skip_console_connect:
                 skip_console_connect='YES'
             else:
                 skip_console_connect=self.global_skip_console_connect

             mgmt_obj=icon.testbedManagement(log,mgmt_dict)

             # Power cycle if specified
             if n_cfg.pwr_cycle:
                 if not n_cfg.pdu_list:
                     log.error('PDU information is not provided for {0}'.format(node))
                     testResult( 'fail', 'PDU information is not provided for {0}'.format(node), log )
                     self.sys_exit_Flag[node] = True
                     self.error_msg[node] = 'PDU information is not provided '

                     sys.exit(1)
                 for pdu_ip,pdu_outlet in n_cfg.pdu_list:
                     try:
                         username=mgmt_obj.pdu[pdu_ip]['login']
                         password=mgmt_obj.pdu[pdu_ip]['password']
                         pwr_status=utils.powerCycle(log,\
                             '-ip {0} -outlet {1} -state down -username {2} -password {3}'\
                             .format(pdu_ip,pdu_outlet,username,password))
                     except:
                         pwr_status=utils.powerCycle(log,'-ip {0} -outlet {1} -state down'\
                             .format(pdu_ip,pdu_outlet))
                     if not pwr_status:
                         log.error('Could not power cycle {0}'.format(node))
                         testResult( 'fail', 'Could not power cycle {0}'.format(node), log )
                         self.sys_exit_Flag[node] = True
                         self.error_msg[node] = 'Could not power cycle'

                         sys.exit(1)
                     if len(n_cfg.pdu_list) > 1:
                         # This sleep is to allow for smooth login to apc
                         time.sleep(1)
                 # Give 5 seconds gap between power down and power up of the chassis
                 time.sleep(5)
                 for pdu_ip,pdu_outlet in n_cfg.pdu_list:
                     try:
                         username=mgmt_obj.pdu[pdu_ip]['login']
                         password=mgmt_obj.pdu[pdu_ip]['password']
                         pwr_status=utils.powerCycle(log,\
                             '-ip {0} -outlet {1} -state up -username {2} -password {3}'\
                             .format(pdu_ip,pdu_outlet,username,password))
                     except:
                         pwr_status=utils.powerCycle(log,'-ip {0} -outlet {1} -state up'\
                             .format(pdu_ip,pdu_outlet))
                     if not pwr_status:
                         log.error('Could not power cycle {0}'.format(node))
                         testResult( 'fail', 'Could not power cycle {0}'.format(node), log )
                         self.sys_exit_Flag[node] = True
                         self.error_msg[node] ='Could not power cycle'
                         sys.exit(1)
                     if len(n_cfg.pdu_list) > 1:
                         # This sleep is to allow for smooth login to apc
                         time.sleep(1)
                 # Give 10 seconds delay for sup console to be available: wierd problem
                 time.sleep(10)

             # Clear consoles if specified
             if n_cfg.clear_console:
                 if n_cfg.sup1_con_ipaddr != 'NA':
                     try:
                         #print("MgmtDict:", mgmt_obj.console_server[n_cfg.sup1_con_ipaddr])
                         username=mgmt_obj.console_server[n_cfg.sup1_con_ipaddr]['login']
                         password=mgmt_obj.console_server[n_cfg.sup1_con_ipaddr]['password']
                         svrType=mgmt_obj.console_server[n_cfg.sup1_con_ipaddr]['svrType']
                         console_status=utils.clearConsole(log,\
                             '-ip {0} -port {1} -username {2} -password {3} -svrType {4}'\
                             .format(n_cfg.sup1_con_ipaddr,n_cfg.sup1_con_port,username,password,svrType))
                     except:
                         console_status=utils.clearConsole(log,'-ip {0} -port {1}'\
                             .format(n_cfg.sup1_con_ipaddr,n_cfg.sup1_con_port))
                     if not console_status:
                         log.error('Could not clear console {0} {1}'\
                             .format(n_cfg.sup1_con_ipaddr,n_cfg.sup1_con_port))
                         testResult( 'fail', 'Could not clear console {0} {1}'.format(n_cfg.sup1_con_ipaddr, \
                              n_cfg.sup1_con_port), log )
                         self.sys_exit_Flag[node] = True
                         self.error_msg[node] = 'Could not clear console'
                         sys.exit(1)
                 if n_cfg.sup2_con_ipaddr != 'NA':
                     try:
                         username=mgmt_obj.console_server[n_cfg.sup2_con_ipaddr]['login']
                         password=mgmt_obj.console_server[n_cfg.sup2_con_ipaddr]['password']
                         svrType=mgmt_obj.console_server[n_cfg.sup1_con_ipaddr]['svrType']
                         console_status=utils.clearConsole(log,\
                             '-ip {0} -port {1} -username {2} -password {3} -svrType {4}'\
                             .format(n_cfg.sup2_con_ipaddr,n_cfg.sup2_con_port,username,password,svrType))
                     except:
                         console_status=utils.clearConsole(log,'-ip {0} -port {1}'\
                             .format(n_cfg.sup2_con_ipaddr,n_cfg.sup2_con_port))
                     if not console_status:
                         log.error('Could not clear console {0} {1}'\
                             .format(n_cfg.sup1_con_ipaddr,n_cfg.sup1_con_port))
                         testResult( 'fail', 'Could not clear console {0} {1}'.format(n_cfg.sup1_con_ipaddr, \
                            n_cfg.sup1_con_port), log )
                         self.sys_exit_Flag[node] = True
                         self.error_msg[node] = 'Could not clear console'
                         sys.exit(1)

             cmd='-ip_addr {0} -user_name {1} -password {2} -device_type {3} -switch_name {4}'\
             .format(n_cfg.mgmt_ip_addr, n_cfg.user_name, n_cfg.password,              \
             n_cfg.device_type, n_cfg.name )

             cmd_ipv6='-ip_addr {0} -user_name {1} -password {2} -device_type {3} -switch_name {4}'\
             .format(n_cfg.mgmt_ipv6_addr, n_cfg.user_name, n_cfg.password,              \
             n_cfg.device_type, n_cfg.name )

             if n_cfg.sup1_con_ipaddr != 'NA' and n_cfg.sup2_con_ipaddr != 'NA':
                 con_cmd='-sup1_con_ipaddr {0} -sup2_con_ipaddr {1} -sup1_con_port {2}      \
                   -sup2_con_port {3} -user_name {4} -password {5} -kickstart_image_uri     \
                   {6} -system_image_uri {7} -single_image_uri {8} -device_type {9}         \
                   -module_type {10} -mgmt_ip_addr {11} -mgmt_prf_len {12}                  \
                   -gateway_addr {13} -pdu_list {14} -switch_name {15} -sup2_boot_mode {16}'\
                   .format( n_cfg.sup1_con_ipaddr, n_cfg.sup2_con_ipaddr,                   \
                   n_cfg.sup1_con_port, n_cfg.sup2_con_port,                                \
                   n_cfg.user_name, n_cfg.password, n_cfg.kickstart_image_uri,              \
                   n_cfg.system_image_uri, n_cfg.single_image_uri, n_cfg.device_type,       \
                   n_cfg.module_type, n_cfg.mgmt_ip_addr, n_cfg.mgmt_prf_len,               \
                   n_cfg.gateway_addr, n_cfg.pdu_list, n_cfg.name, n_cfg.sup2_boot_mode )

             if n_cfg.sup1_con_ipaddr != 'NA' and n_cfg.sup2_con_ipaddr == 'NA':
                 con_cmd='-sup1_con_ipaddr {0} -sup1_con_port {1}                           \
                   -user_name {2} -password {3} -kickstart_image_uri                        \
                   {4} -system_image_uri {5} -single_image_uri {6} -device_type {7}         \
                   -module_type {8} -mgmt_ip_addr {9} -mgmt_prf_len {10} -gateway_addr {11} \
                   -pdu_list {12} -switch_name {13}'.format(                                \
                   n_cfg.sup1_con_ipaddr, n_cfg.sup1_con_port,                              \
                   n_cfg.user_name, n_cfg.password, n_cfg.kickstart_image_uri,              \
                   n_cfg.system_image_uri, n_cfg.single_image_uri, n_cfg.device_type,       \
                   n_cfg.module_type, n_cfg.mgmt_ip_addr, n_cfg.mgmt_prf_len,               \
                   n_cfg.gateway_addr, n_cfg.pdu_list, n_cfg.name )


             if n_cfg.sup1_con_ipaddr == 'NA' and n_cfg.sup2_con_ipaddr != 'NA':
                 con_cmd='-sup2_con_ipaddr {0} -sup2_con_port {1}                           \
                   -user_name {2} -password {3} -kickstart_image_uri                        \
                   {4} -system_image_uri {5} -single_image_uri {6} -device_type {7}         \
                   -module_type {8} -mgmt_ip_addr {9} -mgmt_prf_len {10} -gateway_addr {11} \
                   -pdu_list {12} -switch_name {13}'.format(                                \
                   n_cfg.sup2_con_ipaddr, n_cfg.sup2_con_port,                              \
                   n_cfg.user_name, n_cfg.password, n_cfg.kickstart_image_uri,              \
                   n_cfg.system_image_uri, n_cfg.single_image_uri, n_cfg.device_type,       \
                   n_cfg.module_type, n_cfg.mgmt_ip_addr, n_cfg.mgmt_prf_len,               \
                   n_cfg.gateway_addr, n_cfg.pdu_list, n_cfg.name )


             #print('cmd', cmd)
             if re.search( 'switch', n_cfg.type, flags=re.I ) and \
                 n_cfg.device_type not in ['itgen','fanout']:
                 if n_cfg.mgmt_ip_addr == 'NA':
                     #print('Management IPv4 address is NA, so skipping management connection')
                     log.info('Management IPv4 address is NA, so skipping management connection')
                     self.switch_hdl_dict[node]=False
                 else:
                     hdl=icon.iconssh( log, cmd, mgmt_dict=mgmt_dict)
                     if hdl.hdl.isalive():
                         self.switch_hdl_dict[node]=hdl
                     else:
                         #print('{0}:Could not connect to management connection on IPv4 address'.format(hdl.switchName))
                         log.error('{0}:Could not connect to management connection on IPv4 address'.format(hdl.switchName))
                         testResult( 'fail', '{0}:Could not connect to management connection on IPv4 address'.format(hdl.switchName), log )
                         self.switch_hdl_dict[node]=False

                 if n_cfg.mgmt_ipv6_addr == 'NA':
                     #print('Management IPv6 address is NA, so skipping management connection')
                     log.info('Management IPv6 address is NA, so skipping management connection')
                     self.switch_hdl_ipv6_dict[node]=False
                 else:
                     ipv6_hdl=icon.iconssh( log, cmd_ipv6, mgmt_dict=mgmt_dict)
                     if ipv6_hdl.hdl.isalive():
                         self.switch_hdl_ipv6_dict[node]=ipv6_hdl
                         log.info('Connected to mgmt through IPv6 address')
                     else:
                         #print('{0}:Could not connect to management connection on IPv6 address'.format(hdl.switchName,n_cfg.mgmt_ipv6_addr))
                         log.error('{0}:Could not connect to management connection on IPv6 address'.format(hdl.switchName,n_cfg.mgmt_ipv6_addr))
                         self.switch_hdl_ipv6_dict[node]=False

                 if n_cfg.sup1_con_ipaddr == 'NA' and n_cfg.sup2_con_ipaddr == 'NA':
                     #print('No console info available .. skipping console connection')
                     log.info('No console info available .. skipping console connection')
                 else:
                     #print( 'con_cmd', con_cmd )
                     if not re.search( 'YES', skip_console_connect, re.I ):
                        con_hdl=icon.iconsole( log, con_cmd, mgmt_dict=mgmt_dict)
                        if hasattr(con_hdl,'hdl') and con_hdl.hdl.isalive():
                            self.switch_con_hdl_dict[node]=con_hdl
                        else:
                            #print('Could not connect to console connection')
                            testResult( 'fail', 'Could not connect to console connection', log )
                            log.error('Could not connect to console connection')
                            self.switch_con_hdl_dict[node]=False

                 # Connect to mgmt after configuring it (eg: booted with write erase)
                 if not self.switch_hdl_dict[node]:
                     # If no mgmt and no console then error.
                     if (n_cfg.sup1_con_ipaddr == 'NA' and n_cfg.sup2_con_ipaddr == 'NA') or \
                         (node not in self.switch_con_hdl_dict) or (not self.switch_con_hdl_dict[node]):
                         #print('No console or management connection established to device')
                         testResult( 'fail', 'No console or management connection established to device', log )
                         log.error('No console or management connection established to device')
                         self.switch_dict[node]={}
                         self.switch_hdl_dict[node]={}
                         self.switch_con_hdl_dict[node]={}
                     else:
                         # We have connected to console but not to mgmt 
                         # If mgmt IP/MASK/GW is provided at init, configure 
                         # mgmt intf and connect using iconssh. 
                         if n_cfg.mgmt_ip_addr != 'NA':
                             #print('Configure mgmt interface and connect ssh')
                             log.info('Configure mgmt interface and connect ssh')
                             self.switch_con_hdl_dict[node].configureMgmt('-mgmt_ip_addr {0} \
                                 -mgmt_prf_len {1} -gateway_addr {2}'.format(n_cfg.mgmt_ip_addr,\
                                 n_cfg.mgmt_prf_len, n_cfg.gateway_addr))
                             hdl=icon.iconssh( log, cmd, mgmt_dict=mgmt_dict)
                             if hdl.hdl.isalive():
                                 self.switch_hdl_dict[node]=hdl
                             else:
                                 #print('Could not connect to management connection')
                                 testResult( 'fail', 'Could not connect to management connection', log )
                                 log.error('Could not connect to management connection')
                                 self.switch_hdl_dict[node]=False

                         # If no info available / connect fails then copy console handle to hdl_dict
                         if not self.switch_hdl_dict[node]: 
                             self.switch_hdl_dict[node]=con_hdl
                             #print('Use console handle for hdl_dict also')
                             log.info('Use console handle for hdl_dict also')

                 if self.switch_hdl_dict[node]:
                     self.switch_dict[node]=self.switch_hdl_dict[node].switchName
                 


#==================================================================================#
# createVlans - Class to create list or range of vlans and verify operationaly active 
#==================================================================================#
class createVlans():
    ''' Method to create single or list of vlans and verify it's operational up and active 
    mandatory args: hdl, log, vlan
    -vlans : can input vlan, in a range, or list or any combinations
    Usage Examples: 
    obj=createVlans(hdl,log,'-vlans 800,802-804,807,808,809-810')
    obj=createVlans(hdl,log,'-vlans 991')'''
    def __init__(self, hdl, log, *args):
        self.log=log
        self.hdl=hdl
        self.result='pass'
        arggrammar={}
        arggrammar['vlans']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.vlans=ns.vlans
        # create input vlans and no-shut
        self.log.info('creating vlans : {0}'.format(self.vlans))
        commands='''vlan {0} 
                        no shutdown'''.format(self.vlans)
        self.hdl.configure(commands)
        self.log.info('verifying created vlans {0} are active'.format(self.vlans))
        time.sleep(2)
        if verify_lib.verifyVlans(self.hdl,self.log,'-vlans {0}'.format(self.vlans)).result=='pass':
            self.log.info('vlans {0} are successfully created'.format(self.vlans))
            testResult('pass','{0} created vlans {1} are active'\
                    .format(self.__class__.__name__,self.vlans),self.log)
        else:
            self.log.info('vlans {0} are not active, creation failed'.format(self.vlans))
            testResult('fail','{0} created vlans {1} are not active'\
                    .format(self.__class__.__name__,self.vlans),self.log)


#===========================================================================================#
# deleteVlans - Class to delete list or range of vlans and verify its remval from vlan table 
#===========================================================================================#

class deleteVlans():
    ''' class to delete single or list or range of vlans and verify it's removal from vlan table
    mandatory args: hdl, log, vlan
    -vlans : can input vlan, in a range, or list or any combinations
    Usage Examples: 
    obj=deleteVlans(hdl,log,'-vlans 800,802-804,807,808,809-810')
    obj=deleteVlans(hdl,log,'-vlans 991')'''
    def __init__(self, hdl, log, *args):
        self.log=log
        self.hdl=hdl
        self.result='pass'
        arggrammar={}
        arggrammar['vlans']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.vlans=ns.vlans
        # delete input vlans and no-shut
        self.log.info('deleting vlans : {0}'.format(self.vlans))
        commands='''no vlan {0} '''.format(self.vlans)
        self.hdl.configure(commands)
        self.log.info('verifying deleted vlans {0} are removed from vlan table'.format(self.vlans))
        vlan_list=strtoexpandedlist(ns.vlans)
        # wait for vlan deletion before verification. 
        # TODO: for big vlan range sleep time would need tweaking
        time.sleep(5)
        showvlanbriefdict=getVlanDict(hdl, log)
        for vlan in vlan_list:
            if (str(vlan) not in showvlanbriefdict.keys()):
                testResult('pass','vlan {0} successfully removed from vlan table.'.format(vlan),log)

            elif str(showvlanbriefdict[str(vlan)]['Status'])=='active':
                testResult('fail','vlan {0} not removed, still in active state.'.format(vlan),log)
                continue
            else:
                testResult('fail','vlan {0} not removed, exists in vlan table.'.format(vlan),log)


#==================================================================================#
# addSwitchportAccVlan - enable port in l2 switchport mode access and add access vlan 
#==================================================================================#

class addSwitchportAccVlan():
    ''' class to enable port in switchport mode access and add them to access vlan.
        will create the vlan if not present and then add the access switchports
        Verifies switchport operational mode, its access vlan, and its interface status
    mandatory args: hdl, log, vlan, ports
    optional args: check_link
    -vlans 101
    -ports eth1/1,eth1/6-10
    -check_link up
    note : should give in a single vlan and list/range of ports to add
           to access vlan. Action will not proceed if
           - more than one vlan is passed
    note : should give in a single vlan and list/range/single ports to add as access vlan
           if more than one vlan is given, it will throw error
    Usage Examples: 
    obj=addSwitchportAccVlan(hdl,log,'-vlans 991 -ports eth1/1,eth1/9')
    obj=addSwitchportAccVlan(hdl,log,'-vlans 991 -ports eth102/1/1-3')
    obj=addSwitchportAccVlan(hdl,log,'-vlans 991 -ports eth102/1/1-3 -check_link up')'''

    def __init__(self, hdl, log, *args):
        self.result='pass'
        self.log=log
        self.hdl=hdl
        arggrammar={}
        arggrammar['vlans']='-type str -required true'
        arggrammar['ports']='-type str -required true'
        arggrammar['check_link']='-type str'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.vlans=strtoexpandedlist(ns.vlans)
        self.ports=strtoexpandedlist(ns.ports)
        #intlist=[]
        #for int in strtoexpandedlist(ns.ports):
        #    intlist.append(int.split(".")[1])
        #self.ports=intlist

        self.check_link=ns.check_link

        # check for single vlan input, if more than one fail
        if len(self.vlans) >= 2:
            self.log.info('cannot add multiple input vlans {0} to access port,\
                           please input single vlan. Now exiting'.format(self.vlans))
            testResult('fail','{0} cannot add multiple vlans {0} to access ports {1},\
                        input single vlan'.format(self.vlans, self.ports),log)
            return
        self.vlans=listtostr(self.vlans)
        self.ports=listtostr(self.ports)

        # create input vlans 
        showvlandict=getVlanDict(self.hdl, self.log)
        vlanstocreate=[]
        for vlan in strtoexpandedlist(self.vlans):
            if vlan not in showvlandict.keys() or showvlandict[vlan]['Status'] != 'active':
                vlanstocreate.append(vlan)
        if len(vlanstocreate):
            self.log.info('vlan {0} does not exist or not active'.format(vlanstocreate))
            self.log.info('creating and activating vlan {0}'.format(vlanstocreate))
            create_vlan=createVlans(hdl,log,'-vlans {0}'.format(listtostr(vlanstocreate)))
            if create_vlan.result=='fail':
                self.log.info('creating and activating vlan {0} failed so exiting'.format(vlanstocreate))
                testResult('fail','{0} creation of vlans {1} failed and not active'\
                    .format(self.__class__.__name__,vlanstocreate),self.log)
                return
        # adding port to created vlans in switchport access mode 
        self.log.info('adding input ports {0} to switchport access vlans : {1}'.format(self.ports,self.vlans))
        commands='''interface {0} 
                        switchport
                        switchport mode access
                        switch access vlan {1}
                        no shutdown'''.format(self.ports,self.vlans)
        self.hdl.configure(commands)
        # normalising the input port-list str to match show interface brief output
        ports=normalizeInterfaceName(self.log,self.ports)
        # verify switchport operational mode access on ports
        if verify_lib.verifySwitchportOperMode(self.hdl,self.log,'-sw_oper_mode access -ports {0}\
                        '.format(ports)).result=='pass':
            self.log.info('interface {0} successfully came up in access mode'.format(ports))
        else:
            self.log.info('interface {0} failed to come operationaly in access mode'\
                          .format(ports))
            testResult('fail','{0} interface {1} failed to come up in access mode'\
                       .format(self.__class__.__name__,ports),self.log)
            return
        # verify switchport access vlan added to port
        if verify_lib.verifySwitchportAccessVlan(self.hdl,self.log,'-vlans {0} -ports {1}\
                        '.format(self.vlans,ports)).result=='pass':
            self.log.info('interface {0} added to access vlan {1}'.format(ports,self.vlans))
        else:
            self.log.info('interface {0} not added to access vlan {1}'\
                          .format(ports,self.vlans))
            testResult('fail','{0} on port {1} to access vlan {2} failed '\
                       .format(self.__class__.__name__,ports,self.vlans),self.log)
            return

        # verify physical port status to be up
        # verify link status only if input arg check_link is passed
        if self.check_link:
            if verify_lib.verifyInterfaceStatus(self.hdl,self.log,'-status up -interfaces {0}\
                                -iteration 7 -interval 5'.format(ports)).result=='pass':
                self.log.info('interface {0} successfully up in access mode and access vlan {1}'\
                              .format(ports,self.vlans))
                testResult('pass','port {0} link status check after access vlan {1} addition passed'\
                           .format(ports,self.vlans),self.log)
            else:
                self.log.info('access switchport {0} failed to come up'.format(ports))
                testResult('fail','{0} port {1} status added to access vlan {2} not up '\
                           .format(self.__class__.__name__,ports,self.vlans),self.log)
                return


#==================================================================================#
# removeSwitchportAccVlan - remove port from access vlan  
#==================================================================================#

class removeSwitchportAccVlan():
    ''' class to remove access vlan from the switchports 
    mandatory args: hdl, log, vlan, ports
    optional arg: check_link
       -vlans 101
       -ports eth1/1,eth1/6-10
       -check_link up
    note : should give in a single vlan and list of ports to be removed
           from access vlan. Action will not proceed if
           - more than one vlan is passed
           - if the port is not member of this access vlan 
           - if the port state is not up (only when check_link arg is set), link 
             state check after the action will fail, so will abort
    Usage Examples: 
    obj=removeSwitchportAccVlan(hdl,log,'-vlans 991 -ports eth1/9')
    obj=removeSwitchportAccVlan(hdl,log,'-vlans 991 -ports eth1/9 -check_link up')'''

    def __init__(self, hdl, log, *args):
        self.result='pass'
        self.log=log
        self.hdl=hdl
        arggrammar={}
        arggrammar['vlans']='-type str -required true'
        arggrammar['ports']='-type str -required true'
        arggrammar['check_link']='-type str '
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.vlans=strtoexpandedlist(ns.vlans)
        self.ports=strtoexpandedlist(ns.ports)
        #intlist=[]
        #for int in strtoexpandedlist(ns.ports):
        #    intlist.append(int.split(".")[1])
        #self.ports=intlist
        self.check_link=ns.check_link
        self.default_vlan=1
        # check for single vlan input, if more than one fail
        if len(self.vlans) >= 2:
            self.log.info('cannot remove multiple input vlans {0} from access port,\
                           please input single vlan. Now exiting'.format(self.vlans))
            testResult('abort','{0} cannot remove multiple vlans {1} from access ports {2},\
                        input single vlan'.format(self.__class__.__name__,self.vlans, self.ports),log)
            return
        self.vlans=listtostr(self.vlans)
        self.ports=listtostr(self.ports)
        # normalising the input port-list str to match show interface brief output
        ports=normalizeInterfaceName(self.log,self.ports)

        # verify switchport access vlan membership before removing it from the port 
        if verify_lib.verifySwitchportAccessVlan(self.hdl,self.log,'-vlans {0} -ports {1}\
                        '.format(self.vlans,ports)).result=='pass':
            self.log.info('interface {0} added to access vlan {1}'.format(ports,self.vlans))
        else:
            self.log.info('interface {0} not member of access vlan {1} so cannot remove it'\
                          .format(ports,self.vlans))
            testResult('abort','{0} on port {1} from access vlan {2} cannot proceed, port not member '\
                       .format(self.__class__.__name__,ports,self.vlans),self.log)
            return
        # verify link is up before proceeding if input arg check_link is passed
        if self.check_link:
            if verify_lib.verifyInterfaceStatus(self.hdl,self.log,'-status up -interfaces {0}\
                            -iteration 1 -interval 5'.format(ports)).result=='pass':
                self.log.info('access switchport {0} link up check done '.format(ports))
            else:
                self.log.info('interface {0} link not up cannot proceed with access vlan removal'\
                              .format(ports,self.vlans))
                testResult('abort','{0} port {1} link status check failed, cannot proceed '\
                           .format(self.__class__.__name__,ports,self.vlans),self.log)
                return
        # removing port from input vlan 
        self.log.info('removing input ports {0} from switchport access vlans : {1}'.format(self.ports,self.vlans))
        commands='''interface {0} 
                        no switch access vlan {1}'''.format(self.ports,self.vlans)
        self.hdl.configure(commands)
        # Revisit later
        time.sleep(5)
        # verify switchport access vlan removed from port
        #if verify_lib.verifySwitchportAccessVlan(self.hdl,self.log,'-vlans {0} -ports {1}\
        #                '.format(self.vlans,ports)).result=='pass':
        #    self.log.info('interface {0} is still a member and not removed from access vlan {1}'\
        #                  .format(ports,self.vlans))
        #    testResult('fail','{0} on port {1} from access vlan {2} failed '\
        #               .format(self.__class__.__name__,ports,self.vlans),self.log)
        #    return
        if verify_lib.verifySwitchportAccessVlan(self.hdl,self.log,'-vlans {0} -ports {1}\
                        '.format(self.default_vlan,ports)).result!='pass':
            self.log.info('interface {0} not moved to default vlan after removal from access vlan {1}'\
                          .format(ports,self.vlans))
            testResult('fail','{0} on port {1} from access vlan {2} failed, port not moved to default vlan '\
                       .format(self.__class__.__name__,ports,self.vlans),self.log)
            return

        else:
            self.log.info('interface {0} removed from access vlan {1}'.format(ports,self.vlans))
            self.log.info('interface {0} moved to default access vlan {1}'.format(ports,self.default_vlan))
            testResult('pass','port {0} removal from access vlan {1} passed, port moved to default vlan '\
                       .format(ports,self.vlans),self.log)
            return

        # verify physical port status to be up, after vlan removal
        if verify_lib.verifyInterfaceStatus(self.hdl,self.log,'-status up -interfaces {0}\
                            -iteration 7 -interval 5'.format(ports)).result=='pass':
            self.log.info('interface {0} successfully removed from access vlan {1}'\
                          .format(ports,self.vlans))
            testResult('pass','port {0} link status up after removal from access vlan {1} '\
                       .format(ports,self.vlans),self.log)

        else:
            self.log.info('access switchport {0} failed to come up'.format(ports))
            testResult('fail','{0} port {1} status after removal from access vlan {2} not up '\
                .format(self.__class__.__name__,ports,self.vlans),self.log)
            return



#==================================================================================#
# configSwitchportInfo - Class to configure all access and trunk related switchport info 
#==================================================================================#
class configureSwitchportInfo():
    ''' Configures any switchport access/trunk related params being
        -  mode being access/trunk
        - access vlan
        - trunk allowed vlan
        - trunk allowed vlan add to allowed list
        - trunk allowed vlan remove from allowed list
        - trunk allowed vlan except  
        - trunk native vlan
        - trunk allowed vlan none 
        - trunk allowed vlan all 
    note : use vlan_activate if you need to create vlans being adding 
           also could check link status using port_Status_verify option
           ports : any format of eth or po list,range or combinations are supported
           vlans : any format of list, range or combinations are supported
    mandatory args: hdl, log, ports
        ['ports']='-type str -required true'
    optional arg:
        ['mode']='-type str -choices access,trunk'
        ['access_vlan']='-type str'
        ['allowed_vlans']='-type str'
        ['vlan_activate']='-type str -choices yes'
        ['port_noshut']='-type str -choices yes'
        ['port_status_verify']='-type str -choices yes'
        ['native_vlan']='-type str'
        ['add_vlan']='-type str'
        ['no_vlan']='-type str -choices none'
        ['all_vlan']='-type str -choices all'
        ['except_vlan']='-type str'
        ['remove_vlan']='-type str'
    usage samples:
    obj=configureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -native_vlan 2 -allowed_vlans 1-10 -vlan_activate yes -port_status_verify yes')
    obj=configureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -add_vlan 11-20 -vlan_activate yes -port_status_verify yes')
    obj=configureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -remove_vlan 11-20 -port_status_verify yes')
    obj=configureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -no_vlan none -port_status_verify yes')
    obj=configureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -all_vlan all -port_status_verify yes')
    obj=configureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -except_vlan 4094 -port_status_verify yes')
    obj=configureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode access \
           -access_vlan 999 -vlan_activate yes -port_status_verify yes')
    obj=configureSwitchportInfo(hdl,log,'-ports -po2-3 -mode access \
           -access_vlan 999 -vlan_activate yes -port_status_verify yes')
       '''
 
    def __init__(self, hdl, log, *args):
        ##print '%%%%% entering configureSwitchportInfo class : '
        self.result='pass'
        self.log=log
        self.hdl=hdl
        arggrammar={}
        arggrammar['ports']='-type str -required true'
        arggrammar['mode']='-type str -choices access,trunk'
        arggrammar['access_vlan']='-type str'
        arggrammar['allowed_vlans']='-type str'
        arggrammar['vlan_activate']='-type str -choices yes'
        arggrammar['port_noshut']='-type str -choices yes,no'
        arggrammar['port_status_verify']='-type str -choices yes,no'
        arggrammar['native_vlan']='-type str'
        arggrammar['add_vlan']='-type str'
        arggrammar['no_vlan']='-type str -choices none'
        arggrammar['all_vlan']='-type str -choices all'
        arggrammar['except_vlan']='-type str'
        arggrammar['remove_vlan']='-type str'
        arggrammar['mutualExclusive'] =[('access_vlan','allowed_vlans','add_vlan',\
                   'no_vlan','all_vlan','except_vlan','remove_vlan')]
        arggrammar['mutualExclusive'] =[('no_vlan','vlan_activate')]

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        #self.vlans=strtoexpandedlist(ns.vlans)
        self.ports=ns.ports
        self.expandedportlist=strtoexpandedlist(ns.ports)
        self.mode=ns.mode
        self.accessvlan=ns.access_vlan
        self.nvid=ns.native_vlan
        self.allowvlan=ns.allowed_vlans
        self.addvlan=ns.add_vlan
        self.remvlan=ns.remove_vlan
        self.excvlan=ns.except_vlan
        self.novlan=ns.no_vlan
        ports=normalizeInterfaceName(self.log,self.expandedportlist)
        portstr=listtostr(ports)
        self.result='pass'
        self.createvlan=''
        if ns.access_vlan:
            self.createvlan=ns.access_vlan
            accessvlanlist=strtoexpandedlist(ns.access_vlan)
            vlanstr=listtostr(accessvlanlist)
        elif ns.allowed_vlans:
            self.createvlan=ns.allowed_vlans
        elif ns.add_vlan:
            self.createvlan=ns.add_vlan
        elif ns.all_vlan:
            self.createvlan=ns.all_vlan
        if ns.all_vlan:
            self.allvlan='1-4094'
        # check for single vlan input for adding access vlan, if more than one fail
        if self.mode=='access' and len(accessvlanlist) >= 2:
            self.log.info('Cannot add multiple input vlans {0} to access port,\
                           please input single vlan. Now exiting'.format(self.accessvlan))
            testResult('abort','{0} cannot add multiple vlans {0} to access ports {1},\
                        input single vlan'.format(self.accessvlan, self.ports),log)
            return
 
        # create or activate vlans if activate_vlan arg is set  
        if ns.vlan_activate=='yes':
            self.log.info('Creating and activating vlan {0}'.format(self.createvlan))
            create_vlan=createVlans(hdl,log,'-vlans {0}'.format(self.createvlan))
            if create_vlan.result=='fail':
                self.log.info('Creating and activating vlan {0} failed so exiting'.format(self.createvlan))
                testResult('fail','{0} Creation of vlans {1} failed and not active'\
                    .format(self.__class__.__name__,self.createvlan),self.log)
                return
        # switchport mode config, enable ports in switchport mode access/trunk
        # verify the configured mode 
        if ns.mode:
            ##print '%%%%% configuring switchport mode trunk'
            self.log.info('Configuring ports {0} with mode {1}'.format(self.ports,self.mode))
            commands='''interface {0} 
                            switchport
                            switchport mode {1}'''.format(portstr,self.mode)
            self.hdl.configure(commands)
            time.sleep(10)
            verify1=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-ports {0}\
                             -switchport Enabled -oper_mode {1}'.format(self.ports,self.mode))
            #if verify1.result=='fail':
            #    self.result='fail'
            #    testResult('fail','configuring ports {0} with switchport mode {1} failed'\
            #                .format(self.ports,self.mode), self.log)
            #    return
            #else:
            #    self.log.info('Configuring ports {0} with switchport mode {1} passed'\
            #                    .format(self.ports,self.mode))
 
        # configure access vlan on port and verify 
        if ns.access_vlan:
            ##print '%%%%% configuring switchport access vlan'
            self.log.info('Configuring ports {0} with access vlan {1}'.format(self.ports,self.accessvlan))
            commands='''interface {0} 
                            switchport access vlan {1}
                            no shutdown'''.format(portstr,self.accessvlan)
            self.hdl.configure(commands)
            time.sleep(10)
            verify2=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-ports {0}\
                             -access_vlan {1}'.format(self.ports,self.accessvlan))
            if verify2.result=='fail':
                self.result='fail'
                testResult('fail','Adding port {0} to vlan {1} failed'.format(self.ports,self.accessvlan), self.log)
            else:
                self.log.info('Access port {0} to access vlan {1} passed'.format(self.ports,self.accessvlan))
 
        # configure trunk native vlan on port and verify 
        if ns.native_vlan:
            ##print '%%%%% configuring switchport native vlan'
            self.log.info('configuring ports {0} with trunk native vlan {1}'.format(self.ports,self.nvid))
            commands='''interface {0} 
                            switchport trunk native vlan {1}'''.format(portstr,self.nvid)
            self.hdl.configure(commands)
            verify3=verify_lib.verifySwitchportInfo(self.hdl,self.log,'\
                            -ports {0} -trk_native_vlan {1}'.format(self.ports,self.nvid))
            if verify3.result=='fail':
                self.result='fail'
                testResult('fail','Configuring port {0} with native vlan {1} failed'\
                            .format(self.ports,self.nvid), self.log)
            else:
                self.log.info('Configuring port {0} with native vlan {1} passed'.format(self.ports,self.nvid))

        # configure allowed trunk vlan on port and verify 
        if ns.allowed_vlans:
            ##print '%%%%% configuring switchport allowed vlan'
            self.log.info('configuring ports {0} with trunk allowed vlan {1}'.format(self.ports,self.allowvlan))
            commands='''interface {0} 
                            switchport trunk allowed vlan {1}
                            no shutdown'''.format(portstr,self.allowvlan)
            self.hdl.configure(commands)
            time.sleep(10)
            verify2=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-ports {0}\
                             -trk_allowed_vlan {1}'.format(self.ports,self.allowvlan))
            if verify2.result=='fail':
                self.result='fail'
                testResult('fail','Adding port {0} to vlan {1} failed'.format(self.ports,self.allowvlan), self.log)
            else:
                self.log.info('Adding port {0} to vlan {1} passed'.format(self.ports,self.allowvlan))
 
 
        # configure allowed trunk vlan none on port and verify 
        elif ns.no_vlan:
            ##print '%%%%% configuring switchport no vlan'
            self.log.info('configuring ports {0} with allowed vlans {1}'.format(self.ports,self.novlan))
            commands='''interface {0} 
                            switchport trunk allowed vlan {1}'''.format(portstr,self.novlan)
            self.hdl.configure(commands)
            verify2=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-trk_allowed_vlan_none {0} -ports {1}'\
                                .format(self.novlan,self.ports))
            if verify2.result=='fail':
                testResult('fail','Adding trunk port {0} to vlan {1} failed'.format(self.ports,self.novlan), self.log)
                self.result='fail'
            else:
                self.log.info('Adding trunk port {0} to vlan {1} passed'.format(self.ports,self.novlan))
 
       # configure allowed trunk vlan all '1-4094' on port and verify 
        elif ns.all_vlan:
            ##print '%%%%% configuring switchport all vlan'
            self.log.info('configuring ports {0} with allowed vlans {1}'.format(self.ports,self.allvlan))
            commands='''interface {0} 
                            switchport trunk allowed vlan {1}'''.format(portstr,self.allvlan)
            self.hdl.configure(commands)
            time.sleep(60)
            verify2=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-trk_allowed_vlan_all {0} -ports {1}'\
                                .format(self.allvlan,self.ports))
            #if verify2.result=='fail':
            #    testResult('fail','Adding trunk port {0} to vlan {1} failed'.format(self.ports,self.allvlan), self.log)
            #    self.result='fail'
            #else:
            #    self.log.info('Adding trunk port {0} to vlan {1} passed'.format(self.ports,self.allvlan))
 
        # configure additional trunk vlan to existing allowed list on port and verify 
        elif ns.add_vlan:
            #print '%%%%% configuring switchport add vlan'
            self.log.info('configuring ports {0} with additional vlans {1}'.format(self.ports,self.addvlan))
            commands='''interface {0} 
                            switchport trunk allowed vlan add {1}'''.format(portstr,self.addvlan)
            self.hdl.configure(commands)
            # TODO add verification of added vlan
 
        # remove trunk vlans from existing allowed list on port and verify 
        elif ns.remove_vlan:
            #print '%%%%% configuring switchport remove vlan'
            self.log.info('Removing ports {0} from vlans {1}'.format(self.ports,self.remvlan))
            commands='''interface {0} 
                            switchport trunk allowed vlan remove {1}'''.format(portstr,self.remvlan)
            self.hdl.configure(commands)
            # TODO add verification of vlan removed from the port

        # allow all vlans except the listed on port and verify 
        elif ns.except_vlan:
            #print '%%%%% configuring switchport except vlan'
            self.log.info('configuring ports {0} with all vlan except {1}'.format(self.ports,self.excvlan))
            commands='''interface {0} 
                            switchport trunk allowed vlan except {1}'''.format(portstr,self.excvlan)
            self.hdl.configure(commands)
            # TODO add verification of this vlan membership removal
 
 
        # admin no shut the port, need to verify port state outside 
        # as peer port end state is not known, and can be down
        if ns.port_noshut:
            self.log.info('admin no shut on ports {0}'.format(self.ports))
            commands='''interface {0} 
                            no shutdown'''.format(self.ports)
            self.hdl.configure(commands)
        else:
            self.log.info('admin shut on ports {0}'.format(self.ports))
            commands='''interface {0} 
                            shutdown'''.format(self.ports)
            self.hdl.configure(commands)
 
        if ns.port_status_verify=='yes':
            if verify_lib.verifyInterfaceStatus(self.hdl,self.log,'-status up -interfaces {0}\
                        -iteration 1 -interval 5'.format(ports)).result=='pass':
                self.log.info('Ports {0} link up status check passed '.format(ports))
            else:
                self.log.info('Ports {0} link up status check failed'\
                              .format(ports))
                testResult('fail','{0} port {1} link up status check failed '\
                           .format(self.__class__.__name__,self.ports),self.log)
                return


class unconfigureSwitchportInfo():
    ''' unConfigures any switchport access/trunk related params being
        -  mode being access/trunk
        - access vlan
        - trunk allowed vlan
        - trunk allowed vlan add to allowed list
        - trunk allowed vlan remove from allowed list
        - trunk allowed vlan except
        - trunk native vlan
        - trunk allowed vlan none
        - trunk allowed vlan all
    note : use vlan_activate if you need to create vlans being adding
           also could check link status using port_Status_verify option
           ports : any format of eth or po list,range or combinations are supported
           vlans : any format of list, range or combinations are supported
    mandatory args: hdl, log, ports
        ['ports']='-type str -required true'
    optional arg:
        ['mode']='-type str -choices ["access","trunk"]'
        ['access_vlan']='-type str'
        ['allowed_vlans']='-type str'
        ['vlan_activate']='-type str -choices yes'
        ['port_noshut']='-type str -choices yes'
        ['port_status_verify']='-type str -choices yes'
        ['native_vlan']='-type str'
        ['add_vlan']='-type str'
        ['no_vlan']='-type str -choices none'
        ['all_vlan']='-type str -choices all'
        ['except_vlan']='-type str'
        ['remove_vlan']='-type str'
    usage samples:
    obj=unconfigureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -native_vlan 2 -allowed_vlans 1-10 -vlan_activate yes -port_status_verify yes')
    obj=unconfigureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -add_vlan 11-20 -vlan_activate yes -port_status_verify yes')
    obj=unconfigureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -remove_vlan 11-20 -port_status_verify yes')
    obj=unconfigureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -no_vlan none -port_status_verify yes')
    obj=unconfigureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -all_vlan all -port_status_verify yes')
    obj=unconfigureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode trunk \
           -except_vlan 4094 -port_status_verify yes')
    obj=unconfigureSwitchportInfo(hdl,log,'-ports eth3/3,eth3/4-6 -mode access \
           -access_vlan 999 -vlan_activate yes -port_status_verify yes')
    obj=unconfigureSwitchportInfo(hdl,log,'-ports -po2-3 -mode access \
           -access_vlan 999 -vlan_activate yes -port_status_verify yes')
       '''

    def __init__(self, hdl, log, *args):
        #print '%%%%% entering configureSwitchportInfo class : '
        self.result='pass'
        self.log=log
        self.hdl=hdl
        arggrammar={}
        arggrammar['ports']='-type str -required true'
        arggrammar['mode']='-type str -choices ["access","trunk"]'
        arggrammar['access_vlan']='-type str'
        arggrammar['allowed_vlans']='-type str'
        arggrammar['vlan_activate']='-type str -choices yes'
        arggrammar['port_noshut']='-type str -choices yes'
        arggrammar['port_status_verify']='-type str -choices yes'
        arggrammar['native_vlan']='-type str'
        arggrammar['add_vlan']='-type str'
        arggrammar['no_vlan']='-type str -choices none'
        arggrammar['all_vlan']='-type str -choices all'
        arggrammar['except_vlan']='-type str'
        arggrammar['remove_vlan']='-type str'
        arggrammar['mutualExclusive'] =[('access_vlan','allowed_vlans','add_vlan',\
                   'no_vlan','all_vlan','except_vlan','remove_vlan')]
        arggrammar['mutualExclusive'] =[('no_vlan','vlan_activate')]

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        #self.vlans=strtoexpandedlist(ns.vlans)
        self.ports=ns.ports
        self.expandedportlist=strtoexpandedlist(ns.ports)
        self.mode=ns.mode
        self.accessvlan=ns.access_vlan
        self.nvid=ns.native_vlan
        self.allowvlan=ns.allowed_vlans
        self.addvlan=ns.add_vlan
        self.remvlan=ns.remove_vlan
        self.excvlan=ns.except_vlan
        self.novlan=ns.no_vlan
        ports=normalizeInterfaceName(self.log,self.expandedportlist)
        portstr=listtostr(ports)
        self.result='pass'
        self.createvlan=''
        if ns.access_vlan:
            self.createvlan=ns.access_vlan
            accessvlanlist=strtoexpandedlist(ns.access_vlan)
            vlanstr=listtostr(accessvlanlist)
        elif ns.allowed_vlans:
            self.createvlan=ns.allowed_vlans
        elif ns.add_vlan:
            self.createvlan=ns.add_vlan
        elif ns.all_vlan:
            self.createvlan=ns.all_vlan
        if ns.all_vlan:
            self.allvlan='1-4094'
        # check for single vlan input for adding access vlan, if more than one fail
        if self.mode=='access' and len(accessvlanlist) >= 2:
            self.log.info('Cannot add multiple input vlans {0} to access port,\
                           please input single vlan. Now exiting'.format(self.accessvlan))
            testResult('abort','{0} cannot add multiple vlans {0} to access ports {1},\
                        input single vlan'.format(self.accessvlan, self.ports),log)
            return

        # create or activate vlans if activate_vlan arg is set
        if ns.vlan_activate=='yes':
            self.log.info('Creating and activating vlan {0}'.format(self.createvlan))
            create_vlan=createVlans(hdl,log,'-vlans {0}'.format(self.createvlan))
            if create_vlan.result=='fail':
                self.log.info('Creating and activating vlan {0} failed so exiting'.format(self.createvlan))
                testResult('fail','{0} Creation of vlans {1} failed and not active'\
                    .format(self.__class__.__name__,self.createvlan),self.log)
                return
        # switchport mode config, enable ports in switchport mode access/trunk
        # verify the configured mode
        if ns.mode:
            #print '%%%%% unconfiguring switchport mode '
            #print '%%%%% Mode is : '
            #print ns.mode
            self.log.info('Configuring ports {0} with mode {1}'.format(self.ports,self.mode))
            commands='''interface {0}
                            switchport
                            no switchport mode {1}
                            shutdown
                            no shutdown '''.format(portstr,self.mode)
            self.hdl.configure(commands)
            verify1=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-ports {0}\
                             -switchport Enabled -oper_mode {1}'.format(self.ports,'access'))
            #if verify1.result=='fail':
            #    self.result='fail'
            #    testResult('fail','configuring ports {0} with switchport mode {1} failed'\
            #                .format(self.ports,self.mode), self.log)
            #    return
            #else:
            #    self.log.info('Configuring ports {0} with switchport mode {1} passed'\
            #                    .format(self.ports,self.mode))

        # configure access vlan on port and verify
        if ns.access_vlan:
            #print '%%%%% configuring switchport access vlan'
            self.log.info('Configuring ports {0} with access vlan {1}'.format(self.ports,self.accessvlan))
            commands='''interface {0}
                            no switchport access vlan {1}
                            no shutdown'''.format(portstr,self.accessvlan)
            self.hdl.configure(commands)
            verify2=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-ports {0}\
                             -access_vlan {1}'.format(self.ports,'1'))
            if verify2.result=='fail':
                self.result='fail'
                testResult('fail','Removing port {0} to vlan {1} failed'.format(self.ports,self.accessvlan), self.log)
            else:
                self.log.info('Access port {0} to access vlan {1} passed'.format(self.ports,self.accessvlan))

        # configure trunk native vlan on port and verify
        if ns.native_vlan:
            #print '%%%%% unconfiguring switchport native vlan'
            self.log.info('unconfiguring ports {0} with trunk native vlan {1}'.format(self.ports,self.nvid))
            commands='''interface {0}
                            no switchport trunk native vlan {1}'''.format(portstr,self.nvid)
            self.hdl.configure(commands)
            verify3=verify_lib.verifySwitchportInfo(self.hdl,self.log,'\
                            -ports {0} -trk_native_vlan {1}'.format(self.ports,self.nvid))

            if verify3.result=='fail':
                self.result='fail'
                testResult('fail','unConfiguring port {0} with native vlan {1} failed'\
                            .format(self.ports,self.nvid), self.log)
            else:
                self.log.info('unConfiguring port {0} with native vlan {1} passed'.format(self.ports,self.nvid))

        # unconfigure allowed trunk vlan on port and verify
        if ns.allowed_vlans:
            #print '%%%%% unconfiguring switchport allowed vlan'
            self.log.info('unconfiguring ports {0} with trunk allowed vlan {1}'.format(self.ports,self.allowvlan))
            commands='''interface {0}
                            no switchport trunk allowed vlan {1}
                            shutdown
                            no shutdown'''.format(portstr,self.allowvlan)
            self.hdl.configure(commands)
            #verify2=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-ports {0}\
            #                 -trk_allowed_vlan {1}'.format(self.ports,self.allowvlan))
            #if verify2.result=='fail':
            #    self.result='fail'
            #    testResult('fail','Adding port {0} to vlan {1} failed'.format(self.ports,self.allowvlan), self.log)
            #else:
            #    self.log.info('Adding port {0} to vlan {1} passed'.format(self.ports,self.allowvlan))


        # configure allowed trunk vlan none on port and verify
        elif ns.no_vlan:
            #print '%%%%% unconfiguring switchport no vlan'
            self.log.info('unconfiguring ports {0} with allowed vlans {1}'.format(self.ports,self.novlan))
            commands='''interface {0}
                            no switchport trunk allowed vlan {1}'''.format(portstr,self.novlan)
            self.hdl.configure(commands)
            verify2=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-trk_allowed_vlan_none {0} -ports {1}'\
                                .format(self.novlan,self.ports))
            if verify2.result=='fail':
                testResult('fail','Removing trunk port {0} to vlan {1} failed'.format(self.ports,self.novlan), self.log)
                self.result='fail'
            else:
                self.log.info('Removing trunk port {0} to vlan {1} passed'.format(self.ports,self.novlan))

       # unconfigure allowed trunk vlan all '1-4094' on port and verify
        elif ns.all_vlan:
            #print '%%%%% unconfiguring switchport all vlan'
            self.log.info('unconfiguring ports {0} with allowed vlans {1}'.format(self.ports,self.allvlan))
            commands='''interface {0}
                            no switchport trunk allowed vlan {1}'''.format(portstr,self.allvlan)
            self.hdl.configure(commands)
            time.sleep(60)
            #verify2=verify_lib.verifySwitchportInfo(self.hdl,self.log,'-trk_allowed_vlan_all {0} -ports {1}'\
            #                    .format(self.allvlan,self.ports))
            #if verify2.result=='fail':
            #    testResult('fail','Adding trunk port {0} to vlan {1} failed'.format(self.ports,self.allvlan), self.log)
            #    self.result='fail'
            #else:
            #    self.log.info('Adding trunk port {0} to vlan {1} passed'.format(self.ports,self.allvlan))

        # unconfigure additional trunk vlan to existing allowed list on port and verify
        elif ns.add_vlan:
            #print '%%%%% unconfiguring switchport add vlan'
            self.log.info('unconfiguring ports {0} with additional vlans {1}'.format(self.ports,self.addvlan))
            commands='''interface {0}
                            no switchport trunk allowed vlan add {1}'''.format(portstr,self.addvlan)
            self.hdl.configure(commands)
            # TODO add verification of added vlan

        # remove trunk vlans from existing allowed list on port and verify
        elif ns.remove_vlan:
            #print '%%%%% unconfiguring switchport remove vlan'
            self.log.info('Removing ports {0} from vlans {1}'.format(self.ports,self.remvlan))
            commands='''interface {0}
                            no switchport trunk allowed vlan remove {1}'''.format(portstr,self.remvlan)
            self.hdl.configure(commands)
            # TODO add verification of vlan removed from the port

        # allow all vlans except the listed on port and verify
        elif ns.except_vlan:
            #print '%%%%% unconfiguring switchport except vlan'
            self.log.info('unconfiguring ports {0} with all vlan except {1}'.format(self.ports,self.excvlan))
            commands='''interface {0}
                            no switchport trunk allowed vlan except {1}'''.format(portstr,self.excvlan)
            self.hdl.configure(commands)
            # TODO add verification of this vlan membership removal


        # admin no shut the port, need to verify port state outside
        # as peer port end state is not known, and can be down
        if ns.port_noshut:
            self.log.info('admin no shut on ports {0} }'.format(self.ports))
            commands='''interface {0}
                            no shutdown'''.format(self.ports)
            self.hdl.configure(commands)

        if ns.port_status_verify=='yes':
            if verify_lib.verifyInterfaceStatus(self.hdl,self.log,'-status up -interfaces {0}\
                        -iteration 1 -interval 5'.format(ports)).result=='pass':
                self.log.info('Ports {0} link up status check passed '.format(ports))
            else:
                self.log.info('Ports {0} link up status check failed'\
                              .format(ports))
                testResult('fail','{0} port {1} link up status check failed '\
                           .format(self.__class__.__name__,self.ports),self.log)
                return


######################################################################
## create port-channel  ################
######################################################################
class  createPortChannel():
    ''' Method to configue port-channel interfaces as static or LACP with given set of interfaces
    Sample usage:
    createPortChannel(hdl, log, '-interface Eth3/1,Eth3/2,Eth3/3 -pc_no 10 -mode on')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str -required true'
        arggrammar['mode']='-type str -default active'
        arggrammar['pc_no']='-type int -required true'
        arggrammar['bpdufilter']='-type bool -default False'
        arggrammar['port_status_verify']='-type bool -default True'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pc_mode=parse_output.mode
        pc_no = parse_output.pc_no
        pc='Po{0}'.format(pc_no)
        interface_list=strtolist(parse_output.interface)
        self.result='pass'
        port_list=[]
        for int in interface_list:
            port_list.append(normalizeInterfaceName(log,int))

        if pc_mode=='active':
            hdl.configure('feature lacp')

        if parse_output.bpdufilter:
            sw_cmd='''interface {0} 
                      no shutdown
                      spanning-tree bpdufilter enable
                      channel-group {1} mode {2}
                   '''.format(listtostr(port_list),pc_no,pc_mode)
        else:
            sw_cmd='''interface {0} 
                      no shutdown
                      channel-group {1} mode {2}
                   '''.format(listtostr(port_list),pc_no,pc_mode)

        hdl.configure(sw_cmd)
        time.sleep(5)

        if parse_output.bpdufilter:
            # bpdufilter will be useful when the po 
            # is a fex peer emulating a host
            sw_cmd='''int po{0}
                      spanning-tree bpdufilter enable
                   '''.format(pc_no)
            hdl.configure(sw_cmd)
            time.sleep(5)

        # verify physical port status to be up, after vlan removal
        if parse_output.port_status_verify:
            if verify_lib.verifyPortChannelMembers(hdl,log,'-pc_list {0}'.format(pc_no)).result=='pass':
                log.info('interface port-channel {0} member links are up'\
                      .format(pc_no))
                testResult('pass','interface port-channel {0} member links are not up'\
                   .format(pc_no),log)

            else:
                log.info('interface port-channel {0} member links failed to come up'.format(pc_no))
                testResult('fail','interface port-channel {0} member links are not up '\
                    .format(pc_no),log)

######################################################################
## delete port-channel  ################
######################################################################
class  deletePortChannel():
    ''' Method to delete port-channel interfaces as static or LACP with given set of interfaces
    Sample usage:
    deletePortChannel(hdl, log, '-interface Eth3/1,Eth3/2 -pc_no 10')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str -required true'
        arggrammar['pc_no']='-type int -required true'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pc_no = parse_output.pc_no
        pc='Po{0}'.format(pc_no)
        self.result='pass'
        interface_list=[]
        for int in strtolist(parse_output.interface):
            interface_list.append(normalizeInterfaceName(log,int))
        sw_cmd='''interface {0} 
              no channel-group {1}
           '''.format(listtostr(interface_list),pc_no)
        hdl.configure(sw_cmd)
        time.sleep(3)
        sw_cmd='''no interface {0}'''.format(pc)
        hdl.configure(sw_cmd)
        po_dict=getInterfaceBriefDict(hdl,log)
        for int in interface_list:
            if not normalizeInterfaceName(log,int) in po_dict.keys():
                log.info('interface {0} is not present'.format(int))
                testResult('fail','interface {0} is not present'.format(int),log)
               
            elif (po_dict[normalizeInterfaceName(log,int)]['Port Ch#'] == '--'):
                log.info('interface {0} is removed from PO {1}'.format(int,pc_no))
                testResult('pass','interface {0} is removed from PO {1}'.format(int,pc_no),log)
            else:
                log.info('interface {0} is not removed from PO {1}'.format(int,pc_no))
                testResult('fail','interface {0} is not removed from PO {1}'.format(int,pc_no),log)

######################################################################
## delete member port of a port-channel  ################
######################################################################
class  deleteMemberPortChannel():
    ''' Method to delete the given member of the port-channel interfaces as static or LACP with given set of interfaces
    Sample usage:
    deleteMemberPortChannel(hdl, log, '-interface Eth3/1,Eth3/2 -pc_no 10')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str -required true'
        arggrammar['pc_no']='-type int -required true'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pc_no = parse_output.pc_no
        pc='Po{0}'.format(pc_no)
        self.result='pass'
        interface_list=[]
        for int in strtolist(parse_output.interface):
            interface_list.append(normalizeInterfaceName(log,int))
            sw_cmd='''interface {0} 
                  no channel-group {1}
               '''.format(listtostr(interface_list),pc_no)
            hdl.configure(sw_cmd)
            time.sleep(3)
        po_dict=getInterfaceBriefDict(hdl,log)
        for int in interface_list:
            if not normalizeInterfaceName(log,int) in po_dict.keys():
                log.info('interface {0} is not present'.format(int))
                testResult('fail','interface {0} is not present'.format(int),log)

            elif (po_dict[normalizeInterfaceName(log,int)]['Port Ch#'] == '--'):
                log.info('interface {0} is removed from PO {1}'.format(int,pc_no))
                testResult('pass','interface {0} is removed from PO {1}'.format(int,pc_no),log)
            else:
                log.info('interface {0} is not removed from PO {1}'.format(int,pc_no))
                testResult('fail','interface {0} is not removed from PO {1}'.format(int,pc_no),log)


######################################################################
## Config Feature  ################
######################################################################
class  configFeature():
    ''' Method to configure feature to enable certain features like lacp,ospf,eigrp etc
    Sample usage:
    configFeature(hdl, log, '-feature lacp,ospf,bgp')
    '''
    def __init__(self, hdl, log, *args):
        self.result=configFeature.invoke(hdl,log,*args)
    @staticmethod
    def invoke(hdl, log,*args):
        arggrammar={}
        arggrammar['feature']='-type str -required true'
        arggrammar['listFlag']='-type bool -default True'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        feature_name = parse_output.feature
        result='pass'
        # Below Feature-mapping dict is to map right process during verification
        #for eg: When you enable feature telnet, verifyFeatureState module fails internally while looking for telnet key but internal name got from  DUT is telnetServer, so need to do mapping
        #before we send it for verifyFeatureState.
        FeatureMapping = { 'telnet':'telnetServer', 
                           'scp-server':'scpServer',
                           'ssh':'sshServer' ,
                           'nv overlay':'nve',
                           'vn-segment-vlan-based':'vnseg_vlan' }
        for feature in str.split(feature_name, ','):
            if re.search('hsrp',feature,re.I):
                sw_cmd='''feature hsrp
                        '''
            elif re.search('nve',feature,re.I):
                sw_cmd='''feature nv overlay
                        '''
            elif re.search('vnseg_vlan',feature,re.I):
                sw_cmd='''feature vn-segment-vlan-based
                       ''' 
            elif re.search('nv_overlay_evpn',feature,re.I):
                    hdl.configure('nv overlay evpn')
                    continue
            else:
                    sw_cmd='''feature {0}
                               '''.format(feature)
            hdl.configure(sw_cmd)
 
            tmp_feature=feature
            if feature in FeatureMapping:
                    feature=FeatureMapping[feature]
            if verify_lib.verifyFeatureState(hdl,log,'-feature {0} -listFlag {1}'.format(feature,parse_output.listFlag)).result=='pass':
                log.info('Feature {0} is enabled successfully '\
                .format(tmp_feature))
                #testResult('pass','Feature {0} is enabled successfully '\
                #.format(tmp_feature),log)

            else:
                log.info('Feature {0} is not enabled successfully'.format(tmp_feature))
                #testResult('fail','Feature {0} is not enabled successfully'\
                #.format(feature),log)
                return 'fail'
        return result
######################################################################
## unconfig Feature  ################
######################################################################
class  unconfigFeature():
    ''' Method to un-configure feature to disable certain features like lacp,ospf,eigrp etc
    Sample usage:
    unconfigFeature(hdl, log, '-feature lacp,ospf,bgp')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['feature']='-type str -required true'
        parse_output=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        feature_name = parse_output.feature
        self.result='pass'
        for feature in str.split(feature_name, ','):
            if re.search('hsrp',feature,re.I):
                sw_cmd='no feature hsrp'
            elif re.search('nve',feature,re.I):
                sw_cmd='no feature nv overlay'
            else:
                sw_cmd='''no feature {0} 
                   '''.format(feature)
            hdl.configure(sw_cmd)
            time.sleep(7)
            if verify_lib.verifyFeatureState(hdl,log,'-feature {0} -state disabled'.format(feature)).result=='pass':
                log.info('Feature {0} is disabled successfully '\
                .format(feature))

            else:
                log.error('Feature {0} is not DISABLED successfully'.format(feature))
                return 'fail'



#==================================================================================#
# configSwitchSviInterfaces - Class to configure SVI interfaces on the switch side
#==================================================================================#

class configSwitchSviInterfaces(object):

    def __init__(self, svi_config_dict, switch_dict, switch_hdl_dict ):

        import re
        import icon
        import logging
        import Tkinter

        self.result='pass'
        self.result_message='Test class configSwitchSviInterfaces passed'
        self.log=logging.getLogger('configSwitchSviInterfaces')
        self.log.info('Switch SVI Bringup test')


        try:
             list_of_nodes=svi_config_dict.keys()
        except KeyError:
             #print('svi_config_dict in input file not defined properly ..               \
             #     does not have any keys ..')
             self.result='fail'
             self.result_message='svi_config_dict in input file not defined properly    \
                  does not have any keys ..'
             self.log.error('svi_config_dict in input file not defined properly ..      \
                  does not have any keys ..')


        #print('switch_hdl_dict', switch_hdl_dict )
        for node in list_of_nodes:

          hdl=switch_hdl_dict[node]
          hdl.configure('feature interface-vlan')
          l_args='-show_command {0} -expected_pattern {1}'.format(                  \
                'show system internal feature-mgr feature state | inc interface-vlan', \
                'SUCCESS' )
          hdl.loopUntil(l_args)

          intf_range_list=svi_config_dict[node].keys()

          for svi_int_range in intf_range_list:

             vals=svi_config_dict[node][svi_int_range] 
             parser=argparse.ArgumentParser( prog='configSwitchSviInterfaces' ,         \
                  description='configure SVI interfaces' )
             parser.add_argument( '-start_ipv4_addr', action='store',                   \
                  dest='start_ipv4_addr', required=True )
             parser.add_argument( '-ipv4_mask', action='store',                         \
                  dest='ipv4_mask', required=True )
             parser.add_argument( '-ipv4_addr_step', action='store',                    \
                  dest='ipv4_addr_step', default='0.0.1.0' )
             parser.add_argument( '-vrf_name', action='store',                          \
                  dest='vrf_name', default='default' )
             parser.add_argument( '-secondary_start_ipv4_addr', action='store',         \
                  dest='secondary_start_ipv4_addr' )
             parser.add_argument( '-secondary_ipv4_mask', action='store',               \
                  dest='secondary_ipv4_mask' )
             parser.add_argument( '-secondary_ipv4_addr_step', action='store',          \
                  dest='secondary_ipv4_addr_step', default='0.0.1.0' )

             s_cfg=parser.parse_args(vals.split())


             ipv4_addr=s_cfg.start_ipv4_addr
             self.log.debug('ipv4_addr', ipv4_addr)
             svi_intf_list=normalizeInterfaceName( self.log, strtoexpandedlist(svi_int_range) )
             for intf in svi_intf_list:
                 if s_cfg.vrf_name == "default":
                     config_cmd='''interface {0}
                            ip address {1} {2}
                            no shut'''.format( intf, ipv4_addr,                                                  \
                            s_cfg.ipv4_mask )
                 else:
                     config_cmd='''interface {0}
                            vrf member {1}
                            ip address {2} {3}
                            no shut'''.format( intf, s_cfg.vrf_name, ipv4_addr,                                 \
                            s_cfg.ipv4_mask )
                 hdl.configure(config_cmd)
                 ipv4_addr=utils.incrementIpv4Address( ipv4_addr, s_cfg.ipv4_addr_step )


######################################################################
# Configure L3 interface
######################################################################
class configureL3Interface():
    ''' Method to configue Ipv4 and/or Ipv6 address on an interface
    Sample usage:
    configure_l3_interface(hdl1, log, '-interface Eth3/22 -ip_address 47.1.1.1 -ip_mask 24')
    ipstr='47.1.1.1,47.1.2.1'
    configureL3Interface(hdl1, log, '-interface Eth3/22-23 -ip_address {0} -ip_mask_len 24'.format(ipstr))
    
    '''    
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str -required true'
        arggrammar['ip_address']='-type str -mandatoryargs ip_mask_len'
        arggrammar['ip_mask_len']='-type str -mandatoryargs ip_address'
        arggrammar['ipv6_address']='-type str -mandatoryargs ipv6_mask_len'
        arggrammar['ipv6_mask_len']='-type str -mandatoryargs ipv6_address'
        arggrammar['vrf']='-type str'
        arggrammar['mtu']='-type str'
        arggrammar['sub_intf_vlan']='-type str'
        arggrammar['verify'] = '-type bool -default True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface_list=strtoexpandedlist(ns.interface)
        ip_mask=ns.ip_mask_len
        ipv6_mask=ns.ipv6_mask_len
        self.result='pass'
        int_list=[]
        for int in interface_list:
            int_list.append(normalizeInterfaceName(log,int))
        if ns.vrf:
            if ns.vrf != "default":
                for int in int_list:
                    if re.search('Vlan',int,re.I) or re.search('Lo',int,re.I):
                        sw_cmd='''vrf context {0}
                              interface {1}
                             vrf member {0}'''.format(ns.vrf, int)
                        hdl.configure(sw_cmd)
                    else:
                        sw_cmd='''vrf context {0}
                              interface {1}
                             no switchport
                             vrf member {0}'''.format(ns.vrf, int)
                        hdl.configure(sw_cmd)                     
     
        if ns.ip_address:         
            ipv4_address_list = strtolist(ns.ip_address)
            for int,ip_addr in zip(int_list,ipv4_address_list):
                if re.search('Vlan',int,re.I) or re.search('Lo',int,re.I):
                    sw_cmd='''interface {0}    
                        ip address {1}/{2}
                        no shutdown'''.format(int, ip_addr, ip_mask)    
                else:                
                        sw_cmd='''interface {0}        
                            no switchport
                                ip address {1}/{2}
                                no shutdown'''.format(int, ip_addr, ip_mask)        
                hdl.configure(sw_cmd)
            if ns.verify:
                time.sleep(10)
                if ns.vrf:
                    ipint_dict=getIpv4InterfaceBriefDict(hdl, log, '-vrf {0}'.format(ns.vrf))
                else:
                    ipint_dict=getIpv4InterfaceBriefDict(hdl, log)
                    
                for int,ip_addr in zip(int_list,ipv4_address_list):
                    if int not in ipint_dict.keys():
                            testResult('fail','Interface {0} not in Ipv4 interface dict'.format(int), log)
                            return
                    elif ipint_dict[int]['IP Address']!=ip_addr:
                        testResult('fail','Ip address {0} not configured on interface {1} on {2}'.format(ip_addr,int, hdl.switchName), log)
                    else:
                        testResult('pass','Ip address {0} configured on interface {1} on {2}'.format(ip_addr,int, hdl.switchName), log)
                    
        if ns.ipv6_address:
            ipv6_address_list = strtolist(ns.ipv6_address)
            for int,ipv6_addr in zip(int_list,ipv6_address_list):
                if re.search('Vlan',int,re.I) or re.search('Lo',int,re.I):
                    sw_cmd='''interface {0}    
                        ipv6 address {1}/{2}
                        no shutdown'''.format(int, ipv6_addr, ipv6_mask)    
                else:                
                    sw_cmd='''interface {0} 
                        no switchport
                        ipv6 address {1}/{2}
                        no shutdown'''.format(int, ipv6_addr, ipv6_mask)
                hdl.configure(sw_cmd)
            if ns.verify:
                time.sleep(10)
                if ns.vrf:
                    ipv6int_dict=getIpv6InterfaceBriefDict(hdl, log, '-vrf {0}'.format(ns.vrf))
                else:
                    ipv6int_dict=getIpv6InterfaceBriefDict(hdl, log)
                for int,ipv6_addr in zip(int_list,ipv6_address_list):
                    if int not in ipv6int_dict.keys():
                            testResult('fail','Interface {0} not in Ipv6 interface dict'.format(int),log)
                            return
                    elif ipv6int_dict[int]['IPv6 Address']!=ipv6_addr:
                        testResult('fail','Ipv6 address {0} not configured on interface {1} on {2}'.format(ipv6_addr,int,hdl.switchName), log)
                    else:
                        testResult('pass','Ipv6 address {0} configured on interface {1} on {2}'.format(ipv6_addr,int, hdl.switchName), log)
        if ns.sub_intf_vlan:
            for int in int_list:
                #print int
                sw_cmd='interface {0} \n encapsulation dot1Q {1}'.format(int,ns.sub_intf_vlan)
                hdl.configure(sw_cmd) 

        if ns.mtu:
            mtu_list = strtolist(ns.mtu)
            for int,mtu in zip(int_list,mtu_list):
                if re.search('Vlan',int,re.I) or re.search('Lo',int,re.I):
                    sw_cmd='''interface {0}    
                                mtu {1}'''.format(int, mtu)    
                else:                
                        sw_cmd='''interface {0}        
                                    mtu {1}'''.format(int, mtu)        
                hdl.configure(sw_cmd)

        
######################################################################
## configure access/trunk switchport  ################
######################################################################
class  configureSwitchport():
    ''' Configures a switchport in access/trunk mode with vlans given
    and vlans will be created if not there.
       '''

    def __init__(self, hdl, log, *args):
        self.result='pass'
        self.log=log
        self.hdl=hdl
        arggrammar={}
        arggrammar['vlans']='-type str -required true'
        arggrammar['ports']='-type str -required true'
        arggrammar['mode']='-type str -required true -choices access,trunk'
        arggrammar['mtu']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.vlans=strtoexpandedlist(ns.vlans)
        self.ports=strtoexpandedlist(ns.ports)
        self.mode=ns.mode
        ports=normalizeInterfaceName(self.log,self.ports)
        vlanstr=listtostr(self.vlans)
        portstr=listtostr(ports)
        self.result='pass'
        # check for single vlan input, if more than one fail
        if self.mode=='access' and len(self.vlans) >= 2:
            self.log.info('cannot add multiple input vlans {0} to access port,\
                           please input single vlan. Now exiting'.format(self.vlans))
            testResult('fail','{0} cannot add multiple vlans {0} to access ports {1},\
                        input single vlan'.format(self.vlans, self.ports),log)
            return

        # create input vlans 
        vlandict=getVlanDict(self.hdl, self.log)
        for vlan in self.vlans:
            if vlan not in vlandict.keys():
                self.log.info('creating and  vlan {0}'.format(vlan))
                create_vlan=createVlans(hdl,log,'-vlans {0}'.format(vlan)) 
                if create_vlan.result=='fail':
                    self.log.info('creating and activating vlan {0} failed so exiting'.format(vlanstr))
                    testResult('fail','{0} creation of vlans {1} failed  on {2}'\
                        .format(self.__class__.__name__,self.vlans, self.hdl.switchName),self.log)
                    return
        # switchport access mode  config
        self.log.info('configuring ports {0} in mode {1} vlans : {2}'.format(portstr,self.mode,vlanstr))
        if ns.mode=='access':
            commands='''interface {0} 
                            switchport
                            switchport mode access
                            switch access vlan {1}
                            no shutdown'''.format(portstr,vlanstr)
            self.hdl.configure(commands)
            verify1=verify_lib.verifySwitchportOperMode(self.hdl,self.log,'-sw_oper_mode access -ports {0}'.format(portstr))   
            verify2=verify_lib.verifySwitchportAccessVlan(self.hdl,self.log,'-vlans {0} -ports {1}'.format(vlanstr,portstr))
            if verify1.result=='fail' or verify2.result=='fail':
                 self.result='fail'
                 testResult('fail','Access port config on {0} vlan {1} failed'.format(portstr,vlanstr), self.log)
            else:
                 testResult('pass','Access port config on {0} vlan {1} passed'.format(portstr,vlanstr), self.log)           
                
        # switchport trunk mode  config
        if ns.mode=='trunk':
            commands='''interface {0} 
                        switchport
                        switchport mode trunk
                        switch trunk allowed vlan {1}
                        no shutdown'''.format(portstr,vlanstr)
            self.hdl.configure(commands)
            
            verify3=verify_lib.verifySwitchportOperMode(self.hdl,self.log,'-sw_oper_mode trunk -ports {0}\
                        '.format(portstr))   
            ## Need to add a verify method to verify trunk vlans
            if verify3.result=='fail':
                self.result='fail'
                testResult('fail','Trunk port config on {0} vlan {1} failed'.format(portstr,vlanstr), self.log)           
            else:
                testResult('pass','Trunk port config on {0} vlan {1} passed'.format(portstr,vlanstr), self.log)           
                        
        if ns.mtu:
            commands='''interface {0} 
                            mtu {1}'''.format(portstr,ns.mtu)
            self.hdl.configure(commands)
        





#====================================================================================================#
# configSpanSessions - Configure SPAN sessions and verify the session and ports are operational
#====================================================================================================#


class configSpanSessions(object):

     """ configSpanSessions - Configuration class to create span sessions.
     Usage: 
     configSpanSessions( hdl, log, '-session_no 1 -source_interface_list eth2/1-3,eth5/1,Po11 -dest_interface_list eth5/1"
     configSpanSessions( hdl, log, '-session_no 1 -source_vlan_list 2-10,15 -source_interface_list eth2/1-3,eth5/1,Po11 -dest_interface_list eth5/1"
     configSpanSessions( hdl, log, '-session_no 1 -source_interface_list eth2/1-3,eth5/1,Po11 -dest_interface_list eth5/1 -source_direction tx"
     """

     def __init__( self, hdl, log, *args ):

         arggrammar={}
         arggrammar['session_no']='-type int -default 1'
         arggrammar['source_interface_list']='-type str -required True'
         arggrammar['source_vlan_list']='-type str'
         arggrammar['dest_interface_list']='-type str -required True'
         arggrammar['source_direction']='-choices ["rx","tx","both"] -default both'
         arggrammar['span_dest_mtu']='-type int'

         # Parse the arguments
         ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

         self.result='pass'
         self.hdl=hdl
         self.log=log

         self.log.info('Configuring SPAN session ..')

         # Delete existing session and reconfigure
         cmd='''no monitor session {0}
                monitor session {0}'''.format(ns.session_no)
         hdl.configure(cmd)

         # If Source interfaces are given, configure them
         if ns.source_interface_list:
             for intf in utils.strtoexpandedlist(ns.source_interface_list):
                 cmd='''monitor session {0}
                        source interface {1} {2}'''.format( ns.session_no, intf, ns.source_direction )
                 hdl.configure(cmd)

         # If source vlans are given, configure them
         if ns.source_vlan_list:
             cmd='''monitor session {0}
                    source vlan {1} {2}'''.format( ns.session_no, ns.source_vlan_list, ns.source_direction )
             hdl.configure(cmd)

       
         # Configure the span destination ports in monitor mode..
         for intf in utils.strtoexpandedlist(ns.dest_interface_list): 
              cmd='''interface {0}
                     no switchport
                     switchport
                     switchport monitor
                     no shut'''.format( intf )
              hdl.configure(cmd)


         # Configure the span session with destination ports ..
         for intf in utils.strtoexpandedlist(ns.dest_interface_list): 
              cmd='''monitor session {0}
                    destination interface {1}'''.format( ns.session_no, intf )
              hdl.configure(cmd)


         if ns.span_dest_mtu:
             cmd='''monitor session {0}
                    mtu {1}'''.format( ns.session_no, ns.span_dest_mtu )
       
         cmd='''monitor session {0}
                no shut'''.format( ns.session_no )

         hdl.configure(cmd)
 
         time.sleep(5)


         # Start verifications ..
         # If source vlan list is specified, ensure they are in active state
         if ns.source_vlan_list:
             verify_lib.verifyVlans( self.hdl, self.log, '-vlans {0}'.format(ns.source_vlan_list))


         # Verify if all the source span interfaces are in Up state
         if ns.source_interface_list:
             for intf in utils.strtoexpandedlist(ns.source_interface_list):
                  verify_lib.verifyInterfaceStatus( self.hdl, self.log, '-interfaces {0} -iteration 5 -interval 10 -status up'.format(intf))


         # Verify all the destination span interfaces are in Up state
         for intf in utils.strtoexpandedlist(ns.dest_interface_list): 
              verify_lib.verifyInterfaceStatus( self.hdl, self.log, '-interfaces {0} -iteration 5 -interval 10 -status up'.format(intf))
              show_int=hdl.iexec('show interface {0}'.format(intf))
              if not re.search( 'Switchport monitor is on', show_int, re.I ):
                  testResult( 'fail', 'Span destination port {0} not configured in monitor on mode properly on switch {1}'.format(    \
                      intf, self.hdl.switchName ), self.log )

         show_span=hdl.iexec('show monitor session {0}'.format(ns.session_no))
         pat='state\s+:\sup'
         if not re.search( pat, show_span, re.I ):
             testResult( 'fail', 'Span session {0} failed to come up on switch {1}'.format(ns.session_no, self.hdl.switchName), self.log)

         show_span_int=hdl.iexec('show monitor internal info session {0}'.format(ns.session_no))
         if not re.search( 'SESSION_STATE_OPER_ACTIVE', show_span_int, re.I ):
             testResult('fail', 'Span session {0} is not operationally active on switch {1}'.format(ns.session_no, self.hdl.switchName), self.log)



######################################################################
# Configure Router ISIS 
######################################################################
class configureRouterIsis():
    ''' Method to configue router isis on a node
    Sample usage:
    configureRouterIsis(hdl1, log, '-instance_id 100 -net 47.0004.004d.0001.0001.0c11.1111.00')
    configureRouterIsis(hdl1, log, '-instance_id 100 -net 47.0004.004d.0001.0001.0c11.1111.00 -is-type level-1')

    '''    
    def __init__(self, hdl, log, *args):
        arggrammar = {
            'instance_id': '-type str -required true',
            'net': '-type str',
            'is-type': '-type str',
            'vrf': '-type str',
            }
        ns = parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.result = 'pass'
        hdl.configure('feature isis\n')
        sw_cmd = '''router isis {0}  
               no shutdown'''.format(ns.instance_id)    
        hdl.configure(sw_cmd)
        if ns.net:
            sw_cmd = '''router isis {0}
                net {1}
               '''.format(ns.instance_id, ns.net)    
            hdl.configure(sw_cmd)       
        
        time.sleep(10)
        verify = verify_lib.verifyFeatureState(hdl, log, '-feature isis')
        
######################################################################
# Configure ISIS interface
######################################################################
class configureIsisInterface():
    ''' Method to configue ISIS on an interface
    Sample usage:
    configureIsisInterface(hdl1, log, '-interface eth3/1,eth3/2 -instance_id 100')
    '''    
    def __init__(self, hdl, log, *args):
        arggrammar = {
            'interface': '-type str -required true',
            'instance_id': '-type str -required true',
            'network': '-type str -default bcast',
            'vrf': '-type str -default default',
            }
        ns = parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface_list = strtoexpandedlist(ns.interface)
        self.result = 'pass'
        int_list = []
        for int in interface_list:
            int_list.append(normalizeInterfaceName(log,int))
        
        op = '' if ns.network == 'p2p' else 'no'
        sw_cmd = '''interface {0}    
            ip router isis {1}
            {2} isis network point-to-point
            no shutdown'''.format(listtostr(int_list), ns.instance_id, op)    
        hdl.configure(sw_cmd)
        
        time.sleep(10)
        isis_int_dict = getIsisInterfaceBriefDict(hdl, log, '-vrf {0}'.format(ns.vrf))
        for int in int_list:
            if int not in isis_int_dict.keys():
                testResult('fail','Interface {0} not configured as ISIS interface'.format(int), log)
            else:
                testResult('pass','Interface {0} configured as ISIS interface on {1}'.format(int, hdl.switchName), log)
                    

######################################################################
# Configure Router Ospf
######################################################################
class configureRouterOspf():
    ''' Method to configue router Ospf on a node
    Sample usage:
    configureRouterOspf(hdl1, log, '-instance_id 100 -router_id 1.1.1.1')
    configureRouterOspf(hdl1, log, '-instance_id 100 -router_id 1.1.1.1 -area_id 0.0.0.1,0.0.0.2 -area_type stub,nssa')

    '''    
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['instance_id']='-type str -required true'
        arggrammar['router_id']='-type str'
        arggrammar['area_id']='-type str'
        arggrammar['area_type']='-type str'
        arggrammar['vrf']='-type str'
        arggrammar['bfd']='-type bool -default False'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pid=ns.instance_id
        self.result='pass'
        self.bfd=ns.bfd
        self.vrf=ns.vrf
        
        hdl.configure('feature ospf \n')

        sw_cmd='''router ospf {0}  
               no shutdown'''.format(pid)    
        hdl.configure(sw_cmd)
        if self.bfd:
            if self.vrf == 'default':
                hdl.configure('feature bfd\nrouter ospf {0}\nbfd'.format(pid))
            else:
                hdl.configure('feature bfd\nrouter ospf {0}\nvrf {1}\nbfd'.format(pid,self.vrf))
            verify=verify_lib.verifyFeatureState(hdl, log, '-feature bfd')
        
        if ns.router_id:
            sw_cmd='''router ospf {0}
                router_id {1}
               '''.format(pid, ns.router_id)    
            hdl.configure(sw_cmd)       
        
        time.sleep(10)
        verify=verify_lib.verifyFeatureState(hdl, log, '-feature ospf')

        
        ## Need to add a verify method for router ospf - show ip ospf
        ## Add vrf handling
        


######################################################################
# Configure Router Ospf
######################################################################
class configureRouterOspfv3():
    ''' Method to configue router Ospfv3 on a node
    Sample usage:
    configureRouterOspfv3(hdl1, log, '-instance_id 100 -router_id 1.1.1.1')
    configureRouterOspfv3(hdl1, log, '-instance_id 100 -router_id 1.1.1.1 -area_id 0.0.0.1,0.0.0.2 -area_type stub,nssa')

    '''    
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['instance_id']='-type str -required true'
        arggrammar['router_id']='-type str'
        arggrammar['area_id']='-type str'
        arggrammar['area_type']='-type str'
        arggrammar['vrf']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pid=ns.instance_id
        self.result='pass'
       
        hdl.configure('feature ospfv3 \n')
        
        sw_cmd='''router ospfv3 {0}  
               no shutdown'''.format(pid)    
        hdl.configure(sw_cmd)
        
        if ns.router_id:
            sw_cmd='''router ospfv3 {0}
                router-id {1}
               '''.format(pid, ns.router_id)    
            hdl.configure(sw_cmd)       
        
        time.sleep(10)
        verify=verify_lib.verifyFeatureState(hdl, log, '-feature ospfv3')
        
        ## Need to add a verify method for router ospf - show ip ospf
        ## Add vrf handling
        

       


######################################################################
# Configure Ospf interface
######################################################################
class configureOspfInterface():
    ''' Method to configue Ospf on an interface
    Sample usage:
    configureOspfInterface(hdl1, log, '-interface eth3/1,eth3/2 -ospf_pid 100 area 0.0.0.1')

    '''    
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str -required true'
        arggrammar['instance_id']='-type str -required true'
        arggrammar['area']='-type str -required true'
        arggrammar['vrf']='-type str -default default'
        arggrammar['bfd']='-type bool -default False'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface_list=strtoexpandedlist(ns.interface)
        pid=ns.instance_id
        self.bfd = ns.bfd
        area=ns.area
        self.result='pass'
        int_list=[]
        for int in interface_list:
            int_list.append(normalizeInterfaceName(log,int))
        
        sw_cmd='''interface {0}    
            ip router ospf {1} area {2}
            no shutdown'''.format(listtostr(int_list), pid, area)    
        hdl.configure(sw_cmd)
        if self.bfd:
            hdl.configure('feature bfd\ninterface {0}\nip ospf bfd\nno ip redirects'\
                            .format(listtostr(int_list)))
            verify=verify_lib.verifyFeatureState(hdl, log, '-feature bfd')
        
        time.sleep(10)
        ospf_int_dict=getIpOspfInterfaceBriefDict(hdl, log, '-vrf {0}'.format(ns.vrf))
        for int in int_list:
            if int not in ospf_int_dict.keys():
                testResult('fail','Interface {0} not configured as Ospf interface'.format(int), log)
                return
            elif ospf_int_dict[int]['area']!=area:
                    testResult('fail','Interface {0} configured in ospf area {0} - expected {2} on {3}'.format(int,ospf_int_dict[int]['area'], area, hdl.switchName), log)
            else:
                    testResult('pass','Interface {0} configured in ospf area {1} on {2}'.format(int, area, hdl.switchName), log)
                    


######################################################################
# Configure Ospf interface
######################################################################
class configureOspfv3Interface():
    ''' Method to configue Ospf on an interface
    Sample usage:
    configureOspfv3Interface(hdl1, log, '-interface eth3/1,eth3/2 -instance_id 100 area 0.0.0.1')

    '''    
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str -required true'
        arggrammar['instance_id']='-type str -required true'
        arggrammar['area']='-type str -required true'
        arggrammar['vrf']='-type str -default default'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface_list=strtoexpandedlist(ns.interface)
        pid=ns.instance_id
        area=ns.area
        self.result='pass'
        int_list=[]
        for int in interface_list:
            int_list.append(normalizeInterfaceName(log,int))
        
        sw_cmd='''interface {0}    
            ipv6 router ospfv3 {1} area {2}
            no shutdown'''.format(listtostr(int_list), pid, area)    
        hdl.configure(sw_cmd)
        
        time.sleep(10)
        ospf_int_dict=getIpOspfv3InterfaceBriefDict(hdl, log, '-vrf {0}'.format(ns.vrf))
        for int in int_list:
            if int not in ospf_int_dict.keys():
                testResult('fail','Interface {0} not configured as Ospf interface'.format(int), log)
                return
            elif ospf_int_dict[int]['area']!=area:
                    testResult('fail','Interface {0} configured in ospfv3 area {0} - expected {2} on {3}'.format(int,ospf_int_dict[int]['area'], area, hdl.switchName), log)
            else:
                    testResult('pass','Interface {0} configured in ospfv3 area {1} on {2}'.format(int, area, hdl.switchName), log)
                    



######################################################################
# Configure Route-map
######################################################################
class configureRoutemap():
    ''' Method to configue a route-map
    Sample usage:
    configureRoutemap(hdl1, log, '-name test -seq 20 -action permit')
    configureRoutemap(hdl1, log, '-name test -action deny')
    temp={}
    temp['ip']='address prefix test'
    a=configureRoutemap(hdl1, log, '-name test1 -action permit -seq 100 -match {0}'.format(temp))
    temp['ip']='next-hop 10.1.1.1'
    a=configureRoutemap(hdl1, log, '-name test1 -action permit -set {0}'.format(temp))
    '''    
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['name']='-type str -required true'
        arggrammar['action']='-type str -required true'
        arggrammar['seq']='-type str'
        arggrammar['match']='-type dict'
        arggrammar['set']='-type dict'
        
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        name=ns.name
        self.result='pass'
        int_list=[]
        if ns.seq:
            sw_cmd='route-map {0} {1} {2}'.format(ns.name, ns.action, ns.seq)    
            hdl.configure(sw_cmd)
        else:
            sw_cmd='route-map {0} {1}'.format(ns.name, ns.action)    
            hdl.configure(sw_cmd)
            
        if ns.match:
            if ns.seq:
                for key in ns.match.keys():
                    sw_cmd=''' route-map {0} {1} {2}
                                match {3} {4}'''.format(ns.name, ns.action, ns.seq, key, ns.match[key])
                    hdl.configure(sw_cmd)
            else:
                for key in ns.match.keys():
                    sw_cmd=''' route-map {0} {1}
                                match {2} {3}'''.format(ns.name, ns.action, key, ns.match[key])
                    hdl.configure(sw_cmd)                
                
        if ns.set:
            if ns.seq:
                for key in ns.set.keys():
                    sw_cmd=''' route-map {0} {1} {2}
                                set {3} {4}'''.format(ns.name, ns.action, ns.seq, key, ns.set[key])
                    hdl.configure(sw_cmd)
            else:
                for key in ns.set.keys():
                    sw_cmd=''' route-map {0} {1}
                                set {2} {3}'''.format(ns.name, ns.action, key, ns.set[key])
                    hdl.configure(sw_cmd)               
            
            
        ### Todo : Add getRouteMap and verifyRouteMap methods
        


######################################################################
# Configure Ospf Redistribution
######################################################################
class configureOspfRedistribution():
    ''' Method to configue Ospf redistribution on a node
    Sample usage:
    configureOspfRedistribution(hdl1, log, '-instance_id 100 -type direct -route_map rmap1')
    configureOspfRedistribution(hdl1, log, '-instance_id 100 -type direct,static -route_map rmap1,rmap2'
    '''    
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['instance_id']='-type str -required true'
        arggrammar['type']='-type str -required true'
        arggrammar['route_map']='-type str -required true'
        arggrammar['vrf']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pid=ns.instance_id
        self.result='pass'
        type_list=strtolist(ns.type)
        route_map_list=strtolist(ns.route_map)
        
        if len(type_list)!= len(route_map_list):
            testResult('fail','Number of route-maps given is not same as no of route types given', log)
            return
        
        if ns.vrf and ns.vrf != 'default' :
            for type,route_map in zip(type_list,route_map_list):     
                sw_cmd='''router ospf {0}
                      vrf {1}
                    redistribute {2} route-map {3}
                   '''.format(pid, ns.vrf, type, route_map)    
                hdl.configure(sw_cmd)
        else:
            for type,route_map in zip(type_list,route_map_list):     
                sw_cmd='''router ospf {0}
                    redistribute {1} route-map {2}
                   '''.format(pid, type, route_map)    
                hdl.configure(sw_cmd)            


######################################################################
# Configure Ospfv3 Redistribution
######################################################################
class configureOspfv3Redistribution():
    ''' Method to configue Ospf redistribution on a node
    Sample usage:
    configureOspfRedistribution(hdl1, log, '-instance_id 100 -type direct -route_map rmap1')
    configureOspfRedistribution(hdl1, log, '-instance_id 100 -type direct,static -route_map rmap1,rmap2'
    '''    
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['instance_id']='-type str -required true'
        arggrammar['type']='-type str -required true'
        arggrammar['route_map']='-type str -required true'
        arggrammar['vrf']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pid=ns.instance_id
        self.result='pass'
        type_list=strtolist(ns.type)
        route_map_list=strtolist(ns.route_map)
        
        if len(type_list)!= len(route_map_list):
            testResult('fail','Number of route-maps given is not same as no of route types given', log)
            return
        
        if ns.vrf and ns.vrf != 'default' :
            for type,route_map in zip(type_list,route_map_list):     
                sw_cmd='''router ospfv3 {0}
                      vrf {1}
                    address-family ipv6 unicast
                    redistribute {2} route-map {3}
                   '''.format(pid, ns.vrf, type, route_map)    
                hdl.configure(sw_cmd)
        else:
            for type,route_map in zip(type_list,route_map_list):     
                sw_cmd='''router ospfv3 {0}
                  address-family ipv6 unicast
                    redistribute {1} route-map {2}
                   '''.format(pid, type, route_map)    
                hdl.configure(sw_cmd)            



######################################################################
# Configure Qos/Network-qos/Queuing/Control-plane Classmap
######################################################################
class configClassMap():
    ''' Method to configue qos/network-qos/queuing/control-plane classmaps
    Sample usage:
    configClassMap(hdl, log, '-type qos -name cmap1 -match cos -value 4')

    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['name']='-type str -required True'
        arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -default qos'
        arggrammar['match'] = '-type str -required True'
        arggrammar['value'] = '-type str -required True'
        arggrammar['match_cond'] = '-type str -default match-all'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        match_list=strtolist(ns.match)
        value_list=strtolist(ns.value)
        name=ns.name
        type=ns.type
        match_cond=ns.match_cond
        i=0
        self.result='pass'
        if type == 'qos':
            for match in match_list:
                if re.search( 'access',match,re.I):
                    sw_cmd='''class-map type {0} {1} {2}    
                              match access-group name {3}'''.format(type,match_cond,name,value_list[i])
                    hdl.configure(sw_cmd)
                elif re.search( 'rtp',match,re.I):
                    sw_cmd='''class-map type {0} {1} {2}    
                              match ip {3} {4}'''.format(type,match_cond,name,match,value_list[i])
                    hdl.configure(sw_cmd)
                elif re.search( 'packet',match,re.I):
                    sw_cmd='''class-map type {0} {1} {2}    
                              match packet length {3}'''.format(type,match_cond,name,value_list[i])
                    hdl.configure(sw_cmd)
                elif match_cond:
                    sw_cmd='''class-map type {0} {1} {2}    
                              match {3} {4}'''.format(type,match_cond,name,match,value_list[i])
                    hdl.configure(sw_cmd)
                    i=i+1
                else:    
                    sw_cmd='''class-map type {0} {1}    
                              match {2} {3}'''.format(type,name,match,value_list[i])
                    hdl.configure(sw_cmd)
                    i=i+1
        i=0
        if type == 'network-qos':
            if hdl.device_type == 'N3K':
                match_cond = ''
            else:
                match_cond = 'match-any'
            for match in match_list:
                sw_cmd='''class-map type {0} {1} {2}
                          match {3} {4}'''.format(type,match_cond,name,match,value_list[i])
                hdl.configure(sw_cmd)
                i=i+1
        i=0
        if type == 'queuing':
            if hdl.device_type == 'N3K':
                match_cond = ''
            else:
                match_cond = 'match-any'
            for match in match_list:
                  sw_cmd='''class-map type {0} {1} {2}
                            match {3} {4}'''.format(type,match_cond,name,match,value_list[i])
                  hdl.configure(sw_cmd)
                  i=i+1
        i=0
        class_map_dict=getClassMapDict(hdl,log,'-type {0}'.format(type))
        for match in match_list:
            if re.search( 'access',match,re.I):
                #print ('###Entered here for access-grup###')
                match='access-group'
                #print ('###Match is {0}'.format(match))
            elif re.search( 'dscp',match,re.I):
                #print ('### Entered here for dscp and value is {0} ###'.format(value_list[i]))
                if value_list[i] == 'af11':
                    value_list[i]='10'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af12':
                    value_list[i]='12'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af13':
                    value_list[i]='14'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af21':
                    value_list[i]='18'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af22':
                    value_list[i]='20'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af23':
                    value_list[i]='22'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af31':
                    value_list[i]='26'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af32':
                    value_list[i]='28'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af33':
                    value_list[i]='30'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af41':
                    value_list[i]='34'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af42':
                    value_list[i]='36'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'af43':
                    value_list[i]='38'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'ef':
                    value_list[i]='46'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'cs1':
                    value_list[i]='8'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'cs2':
                    value_list[i]='16'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'cs3':
                    value_list[i]='24'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'cs4':
                    value_list[i]='32'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'cs5':
                    value_list[i]='40'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'cs6':
                    value_list[i]='48'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'cs7':
                    value_list[i]='56'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))
                elif value_list[i] == 'default':
                    value_list[i]='0'
                    #print ('#### Entered here for value liset and value is {0} ###'.format(value_list[i]))

                if class_map_dict[(type,name)][match]==value_list[i]:
                    #print ('###Match is {0}'.format(class_map_dict[(type,name)][match]))
                    testResult('pass','Match {0} value of {1} on class-map {2} configured on {3}'.format(match, value_list[i],name,hdl.switchName), log)
                else:
                    testResult('fail','Match {0} value of {1} on class-map {2} is not configured on {3}'.format(match,value_list[i],name,hdl.switchName), log)
            elif class_map_dict[(type,name)][match]!=value_list[i]:
                #print ('###Match is {0}'.format(match))
                testResult('fail','Match {0} value of {1} on class-map {2} is not configured on {3}'.format(match,value_list[i],name,hdl.switchName), log)
            else:
                testResult('pass','Match {0} value of {1} on class-map {2} configured on {3}'.format(match, value_list[i],name,hdl.switchName), log)
            i=i+1


######################################################################
# Unconfigure Qos/Network-qos/Queuing/Control-plane Classmap
######################################################################
class unconfigClassMap():
    ''' Method to unconfigue qos/network-qos/queuing/control-plane classmaps
    Sample usage:
    unconfigClassMap(hdl, log, '-type qos -name cmap1')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['name']='-type str -required True'
        arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -default qos'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        name=ns.name
        type=ns.type
        self.result='pass'
        if re.search('network-qos', ns.type,re.I):
           sw_cmd='''no class-map type {0} match-any {1}'''.format(type,name)
           hdl.configure(sw_cmd)
        else:
           sw_cmd='''no class-map type {0} {1}'''.format(type,name)
           hdl.configure(sw_cmd)


######################################################################
# Configure Qos/Network-qos/Queuing/Control-plane Policymap
######################################################################
class configPolicyMap():
    ''' Method to configue qos/network-qos/queuing/control-plane policymaps
    Sample usage:
    configPolicyMap(hdl, log, '-type qos -pname pmap1 -cname cmap1 -action cos -value 4')

    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['pname']='-type str -required True'
        arggrammar['cname']='-type str -required True'
        arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -default qos'
        arggrammar['action'] = '-type str -required True'
        arggrammar['value'] = '-type str -required True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        action_list=strtoexpandedlist(ns.action)
        value_list=strtoexpandedlist(ns.value)
        pname=ns.pname
        cname=ns.cname
        type=ns.type
        i=0
        self.result='pass'
        for action in action_list:
            if re.search( 'cos|dscp|precedence|qos-group|discard-class',action,re.I):
              if type == 'qos' and cname == 'class-default':  # 'class type qos class-default' doesn't work, same in N7K
                sw_cmd='''policy-map type {0} {1} 
                          class {2}    
                          set {3} {4}'''.format(type,pname,cname,action,value_list[i])
                hdl.configure(sw_cmd)
              else:
                sw_cmd='''policy-map type {0} {1} 
                          class type {0} {2}    
                          set {3} {4}'''.format(type,pname,cname,action,value_list[i])
                hdl.configure(sw_cmd)
            elif re.search( 'bandwidth',action,re.I):
                if hdl.device_type == 'N3K':
                    sw_cmd='''policy-map type {0} {1}
                          class type {0} {2}
                          {3} percent {4}'''.format(type,pname,cname,action,value_list[i])
                else:
                    sw_cmd='''policy-map type {0} {1}
                          class type {0} {2}
                          {3} remaining percent {4}'''.format(type,pname,cname,action,value_list[i])
                hdl.configure(sw_cmd)
            elif re.search( 'priority',action,re.I):
                if 'level' in value_list:
                    sw_cmd='''policy-map type {0} {1}
                              class type {0} {2}
                              {3} {4}'''.format(type,pname,cname,action,' '.join(value_list))
                    hdl.configure(sw_cmd)
                else:
                    sw_cmd='''policy-map type {0} {1} 
                              class type {0} {2}    
                              {3}'''.format(type,pname,cname,action)
                hdl.configure(sw_cmd)
            elif re.search('pause|random-detect|shape|queue-limit|mtu|congestion-control', action,re.I):  # join all the values for these actions
                sw_cmd='''policy-map type {0} {1} 
                          class type {0} {2}    
                          {3} {4}'''.format(type,pname,cname,action,' '.join(value_list))
                hdl.configure(sw_cmd)
            else:
                sw_cmd='''policy-map type {0} {1} 
                          class type {0} {2}    
                          {3} {4}'''.format(type,pname,cname,action,value_list[i])
                hdl.configure(sw_cmd)
            i=i+1
        i=0
        policy_map_dict=getPolicyMapDict(hdl,log,'-type {0}'.format(type))
        #print ('Dict is {0}'.format(policy_map_dict))
        log.info('Dict is {0}'.format(policy_map_dict))
        log.info('action_list : {0}'.format(action_list))
        for action in action_list:
            if action=='priority':
                if not policy_map_dict[(type,pname)][(type,cname)][action]:
                    testResult('fail','Action {0} value of priority on policy-map {1} is not configured on {2}'.format(action,pname,hdl.switchName), log)
            elif action in ('pause', 'random-detect', 'shape', 'queue-limit', 'mtu', 'congestion-control'):
                if policy_map_dict[(type,pname)][(type,cname)][action].strip()!=' '.join(value_list):
                  if policy_map_dict[(type,pname)][(type,cname)][action].strip()!=value_list[i]:
                    testResult('fail','Action {0} value of {1} on policy-map {2} is not configured on {3}'.format(action,value_list[i],pname,hdl.switchName), log)
                  else:
                    testResult('pass','Action {0} value of {1} on policy-map {2} configured on {3}'.format(action, value_list[i],pname,hdl.switchName), log)
                else:
                  testResult('pass','Action {0} value of {1} on policy-map {2} configured on {3}'.format(action, ' '.join(value_list),pname,hdl.switchName), log)
            i=i+1

######################################################################
# Unconfigure Qos/Network-qos/Queuing/Control-plane Policymap
######################################################################
class unconfigPolicyMap():
    ''' Method to unconfigue qos/network-qos/queuing/control-plane policymaps
    Sample usage:
    unconfigPolicyMap(hdl, log, '-type qos -pname pmap1')

    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['pname']='-type str -required True'
        arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -default qos'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pname=ns.pname
        type=ns.type
        self.result='pass'
        sw_cmd='''no policy-map type {0} {1}'''.format(type,pname)
        hdl.configure(sw_cmd)


######################################################################################
# Applying Qos/Network-qos/Queuing/Control-plane Policymap under Interface/system/vlan
######################################################################################

class applyPolicyMap():
    ''' Method to apply qos/network-qos/queuing/control-plane policymaps under interface/system/vlan
    Sample usage:
    applyPolicyMap(hdl, log, '-type qos -pname pmap1 -target interface -interfaces eth3/3,eth3/4 -dir input')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['pname']='-type str -required True'
        arggrammar['target']='-type str -choices ["interface","system","vlan"] -required True'
        arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -default qos'
        arggrammar['dir'] = '-type str -choices ["input","output"] -default input'
        arggrammar['interfaces']='-type str'
        arggrammar['vlans']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pname=ns.pname
        target=ns.target
        type=ns.type
        dir=ns.dir
        self.result='pass'
        #print ('### Entered here1 applyPolicyMap ###')
        if ns.interfaces:
            int_list=re.findall('('+rex.INTERFACE_NAME+')',ns.interfaces)
        if ns.vlans:
            vlan_list=strtolist(ns.vlans)
        if target=='interface':
            for int in int_list:
                sw_cmd='''interface {0}
                          service-policy type {1} {2} {3}'''.format(int,type,dir,pname)
                hdl.configure(sw_cmd)
        if target=='vlan':
            for vlan in vlan_list:
                sw_cmd='''vlan configuration {0}
                          service-policy type {1} {2} {3}'''.format(vlan,type,dir,pname)
                hdl.configure(sw_cmd)
        if target=='system':
            #print ('### Entered here2 applyPolicyMap ###')
            if type=='network-qos':
                sw_cmd='''system qos
                          service-policy type {0} {1}'''.format(type,pname)
                hdl.configure(sw_cmd)
            if type=='qos':
                #print ('#### Entered here3 for qos ###')
                sw_cmd='''system qos
                          service-policy type {0} {1} {2}'''.format(type,dir,pname)
                hdl.configure(sw_cmd)
            if type=='queuing':
                #print ('#### Entered here4 for queuing ###')
                sw_cmd='''system qos
                          service-policy type {0} {1} {2}'''.format(type,dir,pname)
                hdl.configure(sw_cmd)
######################################################################################
# Removing Qos/Network-qos/Queuing/Control-plane Policymap under Interface/system/vlan
######################################################################################
 
class removePolicyMap():
    ''' Method to remove qos/network-qos/queuing/control-plane policymaps under interface/system/vlan
    Sample usage:
    removePolicyMap(hdl, log, '-type qos -name pmap1 -target interface -interfaces eth3/3,eth3/4 -dir input')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['pname']='-type str -required True'
        arggrammar['target']='-type str -choices ["interface","system","vlan"] -required True'
        arggrammar['type']='-type str -choices ["qos","network-qos","queuing","control-plane"] -default qos'
        arggrammar['dir'] = '-type str -choices ["input","output"] -default input'
        arggrammar['interfaces']='-type str'
        arggrammar['vlans']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        pname=ns.pname
        target=ns.target
        type=ns.type
        dir=ns.dir
        self.result='pass'
        if ns.interfaces:
            int_list=re.findall('('+rex.INTERFACE_NAME+')',ns.interfaces)
        if ns.vlans:
            vlan_list=strtolist(ns.vlans)
        if target=='interface':
            for int in int_list:
                sw_cmd='''interface {0}
                          no service-policy type {1} {2} {3}'''.format(int,type,dir,pname)
                hdl.configure(sw_cmd)
        if target=='vlan':
            for vlan in vlan_list:
                sw_cmd='''vlan configuration {0}
                          no service-policy type {1} {2} {3}'''.format(vlan,type,dir,pname)
                hdl.configure(sw_cmd)

        if target=='system':
            if type=='network-qos':
                sw_cmd='''system qos
                          no service-policy type {0} {1}'''.format(type,pname)
                hdl.configure(sw_cmd)
            if type=='qos':
                sw_cmd='''system qos
                          no service-policy type {0} {1} {2}'''.format(type,dir,pname)
                hdl.configure(sw_cmd)
            if type=='queuing':
                sw_cmd='''system qos
                          no service-policy type {0} {1} {2}'''.format(type,dir,pname)
                hdl.configure(sw_cmd)

### VxLAN config commands API ###

class mapVlanVnid():
    ''' Added by sandesub 
    Method to map a given VLAN-ID to a given VN-segment ID
    Sample usage:
    mapVlanVnid(hdl, log, '-vlan vlan-id -vnid vn-id')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['vlan']='-type str -required True'
        arggrammar['vnid']='-type str -required True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        vlan=ns.vlan
        vnid=ns.vnid
        self.result='pass'
        hdl.configure('vlan {0}\n vn-segment {1}'.format(vlan,vnid))

class configVxLANIntf():
    ''' Added by sandesub 
    Method to configure VxLAN interface parameters: NVE-interface, source-interface, overlay-encap, member-vni, mcast group
    Sample usage:
    configVxLANIntf(hdl, log, '-nve_intf <ethx/y> -src_intf <ethx/y> -member_vnid <> -mcast_grp <>')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['nve_intf']='-type str -required True'
        arggrammar['src_intf']='-type str -required True'
        arggrammar['member_vnid']='-type str -required True'
        arggrammar['mcast_grp']='-type str -required True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        nve_intf=ns.nve_intf
        src_intf=ns.src_intf
        member_vnid=ns.member_vnid
        mcast_grp=ns.mcast_grp
        self.result='pass'
        hdl.configure('interface {0}\n no shutdown \n source-interface loopback {1}\n member vni {2} mcast-group {3}\n'.format(nve_intf,src_intf,member_vnid,mcast_grp))


#### VxLAN APIs end ####
 
class createIPv4ACLEntry():
    ''' Added by sandesub 
    Method to add an ACE entry to an existing/new IPv4 ACL
    Sample usage:
    createIPv4ACLEntry(hdl, log, '-name pacl-ip-1 -action deny -src_ip 1.1.1.2 -src_mask 24 -dst_ip 1.1.1.1 -dst_mask 24')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['name']='-type str -required True'
        arggrammar['action']='-type str -choices ["deny","permit"] -required True'
        arggrammar['src_ip']='-type str -default any'
        arggrammar['src_mask']='-type str'
        arggrammar['dst_ip']='-type str -default any'
        arggrammar['dst_mask']='-type str'
        arggrammar['seq_no']='-type str'
        arggrammar['protocol']='-type str -default ip'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        name=ns.name
        action=ns.action
        src_ip=ns.src_ip
        src_mask=ns.src_mask
        dst_ip=ns.dst_ip
        dst_mask=ns.dst_mask
        seq_no=ns.seq_no
        protocol=ns.protocol
        self.result='pass'

        cmd = 'ip access-list {0}\n'.format(name)
        if ns.seq_no:
            cmd = cmd + str(ns.seq_no) + " "
        cmd = cmd + str(ns.action) + " " + str(ns.protocol) + " " + str(ns.src_ip) 
        if ns.src_mask:
            cmd = cmd + "/" + str(ns.src_mask) + " "
        cmd = cmd + " " + str(ns.dst_ip)     
        if ns.dst_mask:
            cmd = cmd + "/" + str(ns.dst_mask) + " "
        hdl.configure(cmd)
        
        

        


class createIPv6ACLEntry():
    ''' Added by sandesub 
    Method to add an ACE entry to an existing/new IPv6 ACL
    Sample usage:
    createIPv6ACLEntry(hdl, log, '-name pacl-ipv6-1 -action deny -src_ipv6 2001::1:1:1:2 -src_mask 120 -dst_ip 2001::1:1:1:1 -dst_mask 120')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['name']='-type str -required True'
        arggrammar['action']='-type str -choices ["deny","permit"] -required True'
        arggrammar['src_ipv6']='-type str -default any'
        arggrammar['src_mask']='-type str'
        arggrammar['dst_ipv6']='-type str -default any'
        arggrammar['dst_mask']='-type str'
        arggrammar['seq_no']='-type str'
        arggrammar['protocol']='-type str -default ipv6'
        arggrammar['icmp_type']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        name=ns.name
        action=ns.action
        src_ipv6=ns.src_ipv6
        src_mask=ns.src_mask
        dst_ipv6=ns.dst_ipv6
        dst_mask=ns.dst_mask
        seq_no=ns.seq_no
        protocol=ns.protocol
        icmp_type=ns.icmp_type
        self.result='pass'

        cmd = 'ipv6 access-list {0}\n'.format(name)
        if ns.seq_no:
            cmd = cmd + str(ns.seq_no) + " "
        cmd = cmd + str(ns.action) + " " + str(ns.protocol) + " " + str(ns.src_ipv6) 
        if ns.src_mask:
            cmd = cmd + "/" + str(ns.src_mask) + " "
        cmd = cmd + " " + str(ns.dst_ipv6)     
        if ns.dst_mask:
            cmd = cmd + "/" + str(ns.dst_mask) + " "
        if ns.icmp_type:
            cmd = cmd + " " + str(ns.icmp_type)
        hdl.configure(cmd)



class createMACACLEntry():
    ''' Added by sandesub 
    Method to add an ACE entry to an existing/new MAC ACL
    Sample usage:
    createMACACLEntry(hdl, log, '-name pacl-mac-1 -action deny -src_mac 00aa.bbbb.0001 -src_mask 0000.0000.0000 -dst_mac 00aa.bbbb.0002 -dst_mask 0000.0000.0000')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['name']='-type str -required True'
        arggrammar['action']='-type str -choices ["deny","permit"] -required True'
        arggrammar['src_mac']='-type str'
        arggrammar['src_mask']='-type str'
        arggrammar['dst_mac']='-type str'
        arggrammar['dst_mask']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        name=ns.name
        action=ns.action
        src_mac=ns.src_mac
        src_mask=ns.src_mask
        dst_mac=ns.dst_mac
        dst_mask=ns.dst_mask
        self.result='pass'
        hdl.configure('mac access-list {0}\n {1} {2} {3} {4} {5}'.format(name,action,src_mac,src_mask,dst_mac,dst_mask))

class createVACLEntry():
    ''' Added by sandesub 
    Method to add an VACL entry to an existing/new VACL
    Sample usage:
    createVACLEntry(hdl, log, '-name vacl-ipv4-1 -action drop -match_ip_name ipv4-1')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['name']='-type str -required True'
        arggrammar['action']='-type str -choices ["drop","forward","redirect"] -required True'
        arggrammar['match_ip_name']='-type str'
        arggrammar['match_ipv6_name']='-type str'
        arggrammar['match_mac_name']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.result='pass'
        if ns.match_ip_name:
            hdl.configure('vlan access-map {0}\n match ip address {1}\n action {2}'.format(ns.name,ns.match_ip_name,ns.action))
        if ns.match_ipv6_name:
            hdl.configure('vlan access-map {0}\n match ipv6 address {1}\n action {2}'.format(ns.name,ns.match_ipv6_name,ns.action))
        if ns.match_mac_name:
            hdl.configure('vlan access-map {0}\n match mac address {1}\n action {2}'.format(ns.name,ns.match_mac_name,ns.action))



class enableACLStats():
    ''' Added by sandesub 
    Method to enable stats for a ACL
    Sample usage:
    enableACLStats(hdl, log, '-name pacl-ip-1')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['type']='-type str -required True -choices ["ip","mac","vlan","ipv6"]'
        arggrammar['name']='-type str -required True'
        arggrammar['seq']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        name=ns.name
        self.result='pass'
        if ns.type == "ip":
            hdl.configure('ip access-list {0}\n statistics per-entry'.format(name))
        if ns.type == "ipv6":
            hdl.configure('ipv6 access-list {0}\n statistics per-entry'.format(name))
        if ns.type == "mac":
            hdl.configure('mac access-list {0}\n statistics per-entry'.format(name))
        if ns.type == "vlan":
            hdl.configure('vlan access-map {0} {1}\n statistics per-entry'.format(name,ns.seq))
     
class applyACL():
    ''' Added by sandesub 
    Method to apply an ingress/egress ACL to an interface 
    Sample usage:
    applyACL(hdl, log, '-interface Eth4/6 -name pacl-ip-1 -direction in')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str'
        arggrammar['type']='-type str -required True -choices ["ip","pacl-ipv6","mac","racl","racl-ipv6","vlan"]'
        arggrammar['name']='-type str -required True'
        arggrammar['direction']='-type str'
        arggrammar['vlan']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface=ns.interface
        type=ns.type
        name=ns.name
        direction=ns.direction
        vlan=ns.vlan
        self.result='pass'
        if ns.type == "ip":
            hdl.configure('interface {0}\n ip port access-group {1} {2}'.format(interface,name,direction))
        if ns.type == "pacl-ipv6":
            hdl.configure('interface {0}\n ipv6 port traffic-filter {1} {2}'.format(interface,name,direction))
        if ns.type == "racl":
            hdl.configure('interface {0}\n ip access-group {1} {2}'.format(interface,name,direction))
        if ns.type == "racl-ipv6":
            hdl.configure('interface {0}\n ipv6 traffic-filter {1} {2}'.format(interface,name,direction))
        if ns.type == "mac":
            hdl.configure('interface {0}\n mac port access-group {1}\n '.format(interface,name))
        if ns.type == "vlan":
            hdl.configure('vlan filter {0} vlan-list {1}'.format(ns.name,ns.vlan))
    
class removeACL():
    ''' Added by sandesub 
    Method to remove an ingress/egress ACL already applied on an interface 
    Sample usage:
    removeACL(hdl, log, '-interface Eth4/6 -name pacl-ip-1 -direction in')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str'
        arggrammar['type']='-type str -required True -choices ["ip","pacl-ipv6","mac","racl","racl-ipv6","vlan"]'
        arggrammar['name']='-type str -required True'
        arggrammar['direction']='-type str'
        arggrammar['vlan']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface=ns.interface
        name=ns.name
        direction=ns.direction
        self.result='pass'
        if ns.type == "ip":
            hdl.configure('interface {0}\n no ip port access-group {1} {2}'.format(interface,name,direction))
        if ns.type == "pacl-ipv6":
            hdl.configure('interface {0}\n no ipv6 port traffic-filter {1} {2}'.format(interface,name,direction))
        if ns.type == "racl":
            hdl.configure('interface {0}\n no ip access-group {1} {2}'.format(interface,name,direction))
        if ns.type == "racl-ipv6":
            hdl.configure('interface {0}\n no ipv6 traffic-filter {1} {2}'.format(interface,name,direction))
        if ns.type == "mac":
            hdl.configure('interface {0}\n no mac port access-group {1}'.format(interface,name))
        if ns.type == "vlan":
            hdl.configure('no vlan filter {0} vlan-list {1}'.format(name,ns.vlan))
    
class deleteACL():
    ''' Added by sandesub 
    Method to remove a defined ACL by name
    Sample usage:
    deleteACL(hdl, log, '-name pacl-ip-1')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['type']='-type str -required True -choices ["ip","ipv6","mac","vlan"]'
        arggrammar['name']='-type str -required True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        name=ns.name
        self.result='pass'
        if ns.type == "ip":
            hdl.configure('no ip access-list {0}'.format(name))
        if ns.type == "ipv6":
            hdl.configure('no ipv6 access-list {0}'.format(name))
        if ns.type == "mac":
            hdl.configure('no mac access-list {0}'.format(name))
        if ns.type == "vlan":
            hdl.configure('no vlan access-map {0}'.format(name))

class carveTCAM():
    ''' Added by sandesub 
    Method to carve out ACL TCAM regions
    Sample usage:
    carveTCAM(hdl, log, '-region mac-ifacl -size 256')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['region']='-type str -required True -choices ["vpc-convergence","span","redirect","svi","mac-ifacl","mac-vacl","e-ipv6-racl","e-racl","fex-ifacl","fex-ipv6-ifacl","fex-mac-ifacl","ifacl","ipv6-ifacl","ipv6-racl","ipv6-vacl","racl","vacl","qos","vqos","l3qos"]'
        arggrammar['size']='-type str -required True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.result='pass'
        hdl.configure('hardware access-list tcam region {0} {1} '.format(ns.region,ns.size))
        

 
class deleteSVI():
    ''' Added by sandesub 
    Method to delete a SVI
    Sample usage:
    deleteSVI(hdl, log, '-vlan 1')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['vlan']='-type str -required True'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.result='pass'
        if ns.vlan:
            hdl.configure('no int vlan {0}'.format(ns.vlan))
   
class unconfigIP():
    ''' Added by sandesub 
    Method to delete an IPv4 address
    Sample usage:
    unconfigIP(hdl, log,'-interface eth1/1')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str -required true'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.result='pass'
        hdl.configure('interface {0}\n no ip address'.format(ns.interface))

class unconfigIPv6():
    ''' Added by sandesub 
    Method to delete an IPv6 address
    Sample usage:
    unconfigIPv6(hdl, log,'-interface eth1/1')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str -required true'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.result='pass'
        hdl.configure('interface {0}\n no ipv6 address'.format(ns.interface))

class configBpduFilter():
    ''' Added by sandesub 
    Method to apply an STP BPDU filter config to an interface 
    Sample usage:
    configBpduFilter(hdl, log, '-interface Eth1/1 -enable 1')
    '''
    def __init__(self, hdl, log, *args):
        arggrammar={}
        arggrammar['interface']='-type str'
        arggrammar['enable']='-type str'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        interface=ns.interface
        self.result='pass'
        if ns.enable:
            hdl.configure('interface {0}\n spanning-tree bpdufilter enable')
        else:
            hdl.configure('interface {0}\n no spanning-tree bpdufilter')

class configSTPIntf():
    """ Method to configure per-interface STP parameters like cost, port-priority at a per \
        VLAN or per MSTI level"""
    def __init__(self, hdl, log, *args,**stp_dict):
        arggrammar={}
        arggrammar['vlan']='-type str'
        arggrammar['msti']='-type str'
        arggrammar['mutualExclusive'] =[('vlan','msti')]
        arggrammar['cost']='-type str'
        arggrammar['port_priority']='-type str'
        arggrammar['intf']='-type str'
        arggrammar['bpdufilter']='-type str -choices ["enable","disable"]'
        arggrammar['bpduguard']='-type str -choices ["enable","disable"]'
        arggrammar['port_type']='-type str -choices ["edge","edge trunk","normal","network"]'
        arggrammar['guard']='-type str -choices ["loop","root"]'
        arggrammar['lc_issu']='-type str -choices ["auto","disruptive","non-disruptive"]'
        arggrammar['link_type']='-type str -choices ["auto","point-to-point","shared"]'
        arggrammar['unconfig']='-type str'
        argOptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        if stp_dict:
                for interface in stp_dict.keys():
                        for subkey1 in stp_dict[interface].keys():                        
                                for subkey2 in stp_dict[interface][subkey1].keys():
                                        if argOptions.vlan:
                                                if subkey2 == 'Cost':
                                                        hdl.configure ('int {0}\nspanning-tree vlan {1} cost {2}'.format(interface,subkey1,stp_dict[interface][subkey1][subkey2]))
                                                if subkey2 == 'Port_Priority':
                                                        hdl.configure ('int {0}\nspanning-tree vlan {1} port-priority {2}'.format(interface,subkey1,stp_dict[interface][subkey1][subkey2]))
                                        if argOptions.msti:
                                                if subkey2 == 'Cost':
                                                        hdl.configure ('int {0}\nspanning-tree mst {1} cost {2}'.format(interface,subkey1,stp_dict[interface][subkey1][subkey2]))
                                                if subkey2 == 'Port_Priority':
                                                        hdl.configure ('int {0}\nspanning-tree mst {1} port-priority {2}'.format(interface,subkey1,stp_dict[interface][subkey1][subkey2]))
        else:
                if argOptions.vlan:
                        if argOptions.cost:
                                hdl.configure ('int {2}\nspanning-tree vlan {0} cost {1}'.format(argOptions.vlan,argOptions.cost,argOptions.intf))
                        if argOptions.port_priority:
                                hdl.configure ('int {2}\nspanning-tree vlan {0} port-priority {1}'.format(argOptions.vlan,argOptions.port_priority,argOptions.intf))
                if argOptions.msti:
                        if argOptions.cost:
                                hdl.configure ('int {2}\nspanning-tree mst {0} cost {1}'.format(argOptions.msti,argOptions.cost,argOptions.intf))
                        if argOptions.port_priority:
                                hdl.configure ('int {2}\nspanning-tree mst {0} port-priority {1}'.format(argOptions.msti,argOptions.port_priority,argOptions.intf))
                if (not argOptions.vlan) and (not argOptions.msti):
                        if argOptions.cost:
                                hdl.configure ('int {1}\nspanning-tree cost {0}'.format(argOptions.cost,argOptions.intf))
                        if argOptions.port_priority:
                                hdl.configure ('int {1}\nspanning-tree port-priority {0}'.format(argOptions.port_priority,argOptions.intf))
                        if argOptions.guard:
                                hdl.configure ('int {1}\nspanning-tree guard {0}'.format(argOptions.guard,argOptions.intf))
                        if argOptions.lc_issu:
                                hdl.configure ('int {1}\nspanning-tree lc-issu {0}'.format(argOptions.lc_issu,argOptions.intf))
                        if argOptions.link_type:
                                hdl.configure ('int {1}\nspanning-tree link-type {0}'.format(argOptions.link_type,argOptions.intf))
                        if argOptions.bpdufilter:
                            hdl.configure ('int {0}\n spanning-tree bpdufilter {1}'.format(argOptions.intf,argOptions.bpdufilter))
                        if argOptions.bpduguard:
                            hdl.configure ('int {0}\n spanning-tree bpduguard {1}'.format(argOptions.intf,argOptions.bpduguard))
                        if argOptions.port_type:
                            hdl.configure ('int {0}\n spanning-tree port type {1}'.format(argOptions.intf,argOptions.port_type))
        
class unconfigSTPIntf():
    """ Method to un-configure per-interface STP parameters like cost, port-priority at a per \
    VLAN or per MSTI level.
    Added by sandesub  
    """
    def __init__(self, hdl, log, *args,**stp_dict):
        arggrammar={}
        arggrammar['vlan']='-type str'
        arggrammar['msti']='-type str'
        arggrammar['mutualExclusive'] =[('vlan','msti')]
        arggrammar['cost']='-type str'
        arggrammar['port_priority']='-type str'
        arggrammar['intf']='-type str'
        arggrammar['bpdufilter']='-type str -choices ["enable","disable"]'
        arggrammar['bpduguard']='-type str -choices ["enable","disable"]'
        arggrammar['port_type']='-type str -choices ["edge","edge trunk","normal","network"]'
        arggrammar['guard']='-type str -choices ["loop","root"]'
        arggrammar['lc_issu']='-type str -choices ["auto","disruptive","non-disruptive"]'
        arggrammar['link_type']='-type str -choices ["auto","point-to-point","shared"]'
        arggrammar['unconfig']='-type str'
        argOptions=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        if stp_dict:
                for interface in stp_dict.keys():
                        for subkey1 in stp_dict[interface].keys():                        
                                for subkey2 in stp_dict[interface][subkey1].keys():
                                        if argOptions.vlan:
                                                if subkey2 == 'Cost':
                                                        hdl.configure ('int {0}\nno spanning-tree vlan {1} cost'.format(interface,subkey1))
                                                if subkey2 == 'Port_Priority':
                                                        hdl.configure ('int {0}\nno spanning-tree vlan {1} port-priority'.format(interface,subkey1))
                                        if argOptions.msti:
                                                if subkey2 == 'Cost':
                                                        hdl.configure ('int {0}\nno spanning-tree mst {1} cost'.format(interface,subkey1))
                                                if subkey2 == 'Port_Priority':
                                                        hdl.configure ('int {0}\nno spanning-tree mst {1} port-priority'.format(interface,subkey1))
        else:
                if argOptions.vlan:
                        if argOptions.cost:
                                hdl.configure ('int {0}\nno spanning-tree vlan {1} cost'.format(argOptions.intf,argOptions.vlan))
                        if argOptions.port_priority:
                                hdl.configure ('int {0}\nno spanning-tree vlan {1} port-priority'.format(argOptions.intf,argOptions.vlan))
                if argOptions.msti:
                        if argOptions.cost:
                                hdl.configure ('int {0}\nno spanning-tree mst {1} cost'.format(argOptions.intf,argOptions.msti))
                        if argOptions.port_priority:
                                hdl.configure ('int {0}\nno spanning-tree mst {1} port-priority'.format(argOptions.intf,argOptions.msti))
                if (not argOptions.vlan) and (not argOptions.msti):
                        if argOptions.cost:
                                hdl.configure ('int {0}\nno spanning-tree cost'.format(argOptions.intf))
                        if argOptions.port_priority:
                                hdl.configure ('int {0}\nno spanning-tree port-priority'.format(argOptions.intf))
                        if argOptions.guard:
                                hdl.configure ('int {0}\nno spanning-tree guard'.format(argOptions.intf))
                        if argOptions.lc_issu:
                                hdl.configure ('int {0}\nno spanning-tree lc-issu'.format(argOptions.intf))
                        if argOptions.link_type:
                                hdl.configure ('int {0}\nno spanning-tree link-type'.format(argOptions.intf))
                        if argOptions.bpdufilter:
                            hdl.configure ('int {0}\n no spanning-tree bpdufilter'.format(argOptions.intf))
                        if argOptions.bpduguard:
                            hdl.configure ('int {0}\n no spanning-tree bpduguard'.format(argOptions.intf))
                        if argOptions.port_type:
                            hdl.configure ('int {0}\n no spanning-tree port type'.format(argOptions.intf))
                
class configSTPGlobal():
    """ Method to configure global STP parameters\
        Added by sandesub
    """
    def __init__(self, hdl, log, *args,**stp_dict):
        arggrammar={}
        arggrammar['mode']='-type str -choices ["rapid-pvst","mst"] -default rapid-pvst'
        arggrammar['ba']='-type str -default 0'
        arggrammar['domain']='-type str'
        arggrammar['lc_issu']='-type str -choices ["auto","disruptive","non-disruptive"]'
        arggrammar['loopguard']='-type str -default 0'
        arggrammar['pathcost_method']='-type str -choices ["short","long"] -default short'
        arggrammar['bpdufilter']='-type str -default 0'
        arggrammar['bpduguard']='-type str -default 0'
        arggrammar['edge']='-type str -default 0'
        arggrammar['network']='-type str -default 0'
        arggrammar['vlan']='-type str'
        arggrammar['mst']='-type str'
        arggrammar['forward_time']='-type str'
        arggrammar['hello_time']='-type str'
        arggrammar['max_age']='-type str'
        arggrammar['priority']='-type str'
        arggrammar['root']='-type str'
        arggrammar['name']='-type str'
        arggrammar['revision']='-type str'
        arggrammar['pvlan_sync']='-type str -default 0'
        arggrammar['instance']='-type str'
        
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        if ns.mode:
            hdl.configure('spanning-tree mode {0}'.format(ns.mode))
        if ns.ba:
            hdl.configure('spanning-tree bridge assurance')
        if ns.domain:
            hdl.configure('spanning-tree domain {0}'.format(ns.domain))
        if ns.lc_issu:
            hdl.configure('spanning-tree lc-issu {0}'.format(ns.lc_issu))
        if ns.loopguard:
            hdl.configure('spanning-tree loopguard default')
        if ns.pathcost_method:
            hdl.configure('spanning-tree pathcost method {0}'.format(ns.pathcost_method))
        if ns.bpdufilter:
            hdl.configure('spanning-tree port type edge bpdufilter default')
        if ns.bpduguard:
            hdl.configure('spanning-tree port type edge bpduguard default')
        if ns.edge:
            hdl.configure('spanning-tree port type edge default')
        if ns.network:
            hdl.configure('spanning-tree port type network default')
        if ns.vlan:
            if ns.forward_time:
                hdl.configure('spanning-tree vlan {0} forward-time {1}'.format(ns.vlan,ns.forward_time))
            if ns.hello_time:
                hdl.configure('spanning-tree vlan {0} hello-time {1}'.format(ns.vlan,ns.hello_time))
            if ns.max_age:
                hdl.configure('spanning-tree vlan {0} max-age {1}'.format(ns.vlan,ns.max_age))
            if ns.priority:
                hdl.configure('spanning-tree vlan {0} priority {1}'.format(ns.vlan,ns.priority))
            if ns.root:
                hdl.configure('spanning-tree vlan {0} root {1}'.format(ns.vlan,ns.root))
        if ns.mst:
            if ns.priority:
                hdl.configure('spanning-tree mst {0} priority {1}'.format(ns.mst,ns.priority))
            if ns.root:
                hdl.configure('spanning-tree mst {0} root {1}'.format(ns.mst,ns.root))
        if ns.name:
            hdl.configure('spanning-tree mst configuration\n name {0}'.format(ns.name))
        if ns.revision:
            hdl.configure('spanning-tree mst configuration\n revision {0}'.format(ns.revision))
        if ns.instance:
            hdl.configure('spanning-tree mst configuration\n instance {0} vlan {1}'.format(ns.instance,ns.vlan))
        if ns.pvlan_sync:
            hdl.configure('spanning-tree mst configuration\n private-vlan synchronize')
                
class unconfigSTPGlobal():
    """ Method to un-configure global STP parameters\
        Added by sandesub
    """
    def __init__(self, hdl, log, *args,**stp_dict):
        arggrammar={}
        arggrammar['mode']='-type str -choices ["rapid-pvst","mst"] -default rapid-pvst'
        arggrammar['ba']='-type str -default 0'
        arggrammar['domain']='-type str'
        arggrammar['lc_issu']='-type str -choices ["auto","disruptive","non-disruptive"]'
        arggrammar['loopguard']='-type str -default 0'
        arggrammar['pathcost_method']='-type str -choices ["short","long"] -default short'
        arggrammar['bpdufilter']='-type str -default 0'
        arggrammar['bpduguard']='-type str -default 0'
        arggrammar['edge']='-type str -default 0'
        arggrammar['network']='-type str -default 0'
        arggrammar['vlan']='-type str'
        arggrammar['mst']='-type str'
        arggrammar['forward_time']='-type str'
        arggrammar['hello_time']='-type str'
        arggrammar['max_age']='-type str'
        arggrammar['priority']='-type str'
        arggrammar['root']='-type str'
        arggrammar['name']='-type str'
        arggrammar['revision']='-type str'
        arggrammar['pvlan_sync']='-type str -default 0'
        arggrammar['instance']='-type str'
        
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        if ns.mode:
            hdl.configure('no spanning-tree mode')
        if ns.ba:
            hdl.configure('no spanning-tree bridge assurance')
        if ns.domain:
            hdl.configure('no spanning-tree domain {0}'.format(ns.domain))
        if ns.lc_issu:
            hdl.configure('no spanning-tree lc-issu')
        if ns.loopguard:
            hdl.configure('no spanning-tree loopguard default')
        if ns.pathcost_method:
            hdl.configure('no spanning-tree pathcost method')
        if ns.bpdufilter:
            hdl.configure('no spanning-tree port type edge bpdufilter default')
        if ns.bpduguard:
            hdl.configure('no spanning-tree port type edge bpduguard default')
        if ns.edge:
            hdl.configure('no spanning-tree port type edge default')
        if ns.network:
            hdl.configure('no spanning-tree port type network default')
        if ns.vlan:
            if ns.forward_time:
                hdl.configure('no spanning-tree vlan {0} forward-time'.format(ns.vlan))
            if ns.hello_time:
                hdl.configure('no spanning-tree vlan {0} hello-time'.format(ns.vlan))
            if ns.max_age:
                hdl.configure('no spanning-tree vlan {0} max-age'.format(ns.vlan))
            if ns.priority:
                hdl.configure('no spanning-tree vlan {0} priority'.format(ns.vlan))
            if ns.root:
                hdl.configure('no spanning-tree vlan {0} root'.format(ns.vlan))
        if ns.mst:
            if ns.priority:
                hdl.configure('no spanning-tree mst {0} priority'.format(ns.mst))
            if ns.root:
                hdl.configure('no spanning-tree mst {0} root'.format(ns.mst))
        if ns.name:
            hdl.configure('spanning-tree mst configuration\n no name')
        if ns.revision:
            hdl.configure('spanning-tree mst configuration\n no revision')
        if ns.instance:
            hdl.configure('spanning-tree mst configuration\n no instance {0}'.format(ns.instance))
        if ns.pvlan_sync:
            hdl.configure('spanning-tree mst configuration\n no private-vlan synchronize')




class trafficConnectPorts(object):

    """
    Class to configure ingress traffic points on the switch.
    This will have all interface and associated verification
    traffic_connect_ports:
      node01:
         interfaces:
            Eth1/1: -port_mode routed -ip_address 1.1.1.1 mask 24 -vrf vrf1

      node02:
         interfaces:
            Eth1/1: -port_mode access -vlan 3 

      node03:
         interfaces:
            Eth1/1: -port_mode trunk -vlan 3-10
    """
  

    def __init__(self,switch_hdl_dict,port_config,log,*args):
        
        self.result='pass'
        self.log = log
        self.unconfigure = False
        if type(port_config) != dict:
             testResult ('fail', 'port Config is not in dictionary format',self.log)
             self.result = 'fail'
             return
        else:
             self.port_config=port_config
        if type(switch_hdl_dict) != dict:
             testResult ('fail', 'switch Handles and Names not in dictionary format',self.log)
             self.result = 'fail'
             return
        else:
             self.hdl=switch_hdl_dict
        
    def configInterfaces(self,node,interface,args):
         """Method to configure an interface"""

         arggrammar = {}
         arggrammar['port_mode'] = '-type str -choices ["access","trunk","routed"] -default access'
         arggrammar['vlan'] = '-type str -format {0}'.format(rex.VLAN_RANGE)
         arggrammar['vrf'] = '-type str -format {0}'.format(rex.VRF_NAME)
         arggrammar['ip_address'] = '-type str -format {0}'.format(rex.IPv4_ADDR)
         arggrammar['mask'] = '-type str -format {0}'.format(rex.NUM)
         arggrammar['oneMandatory']=[('vlan','ip_address')]
         arggrammar['mutualExclusive']=[('vlan','ip_address')]
         parse = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
         if parse.port_mode == 'routed':
             params = '-interface {0} -ip_address {1} -ip_mask_len {2}'\
                 .format(interface,parse.ip_address,parse.mask)
             if parse.vrf: params += ' -vrf {0}'.format(parse.vrf)
             configureL3Interface(self.hdl[node],self.log,params)                                     
         else:
             configureSwitchport(self.hdl[node],self.log,'-ports {0} -mode {1} -vlans {2}'.\
                                     format(interface,parse.port_mode,parse.vlan))
                                 
    def config(self):
        """
        Configure all interfaces connected to traffic end points 
        """
        for node in self.port_config.keys():
            if 'interfaces' in self.port_config[node].keys():
                for interface in self.port_config[node]['interfaces'].keys():
                    if self.unconfigure: 
                        utils.clearInterfaceConfig(self.hdl[node],self.log,'-interface {0}'.format(interface))
                    else:
                        utils.clearInterfaceConfig(self.hdl[node],self.log,'-interface {0}'.format(interface))
                        self.configInterfaces(node,interface,self.port_config[node]['interfaces'][interface])
                        #Ignore status check of FEX interfaces
                        if re.match(rex.FEX_INTERFACE_TYPE,interface):
                            continue
                        obj= verify_lib.verifyInterfaceStatus(\
                            self.hdl[node],self.log,'-interfaces {0} -iteration 3 -status up'.format(interface))
                        if obj.result == 'fail':
                            testResult('fail', 'Failed:interface {0} not up on {1}'.format(interface,node),self.log)
                            self.result = 'fail'
    def unconfig(self):
        """
        Method to unconfigure all interfaces connected to traffic generators
        """
        self.unconfigure = True
        self.config()
        self.unconfigure = False






class enableSnmpTraps(object):

   """ Class to enable all supported SNMP traps in NXOS"""

   def __init__( self, hdl, log, *args ):

        arggrammar={}
        arggrammar['trap_type']='-type str -default all'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

        if ns.trap_type == "all":
            cmd = 'show snmp trap | inc :'
        else:
            cmd = 'show snmp traps | inc {0}'.format(ns.trap_type)

        show_snmp=hdl.iexec(cmd)
        pat='([a-zA-Z0-9\-\_]+)\s+: ([a-zA-Z0-9\-\_]+)\s+([Yes|No])'
        lines=re.findall( pat, show_snmp, re.I )

        pattern='([a-zA-Z0-9\-\_]+)\s+\: ([a-zA-Z0-9\-\_]+)\s+([Yes|No])'
        for line in lines:
           (trap_type, trap_name, en_flag)=line
           config_cmd='snmp-server enable traps {0} {1}'.format(trap_type, trap_name)
           hdl.configure(config_cmd)

class enableTacacsPlus(object):

   """ Class to enable tacacs+ server """

   def __init__( self, hdl, log, *args ):

        arggrammar={}
        arggrammar['tac_server'] = '-type str -required True -format {0}'.format(rex.IPv4_ADDR)
        arggrammar['key']='-type str -required True '
        arggrammar['vrf'] = '-type str -default management -format {0}'.format(rex.VRF_NAME)
        arggrammar['aaa_grp'] = '-type str -default tac1'
        arggrammar['authentication'] = '-type bool -default True'
        arggrammar['authorization'] = '-type bool -default True'
        arggrammar['accounting'] = '-type bool -default True'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

        configFeature(hdl, log, '-feature tacacs')
        cmd = 'tacacs-server host {0} key {1}\n'.format(ns.tac_server,ns.key)
        cmd = cmd + 'aaa group server tacacs+ {0}\n'.format(ns.aaa_grp)
        cmd = cmd + 'server {0}\n'.format(ns.tac_server)
        if ns.vrf:
            cmd = cmd + 'use-vrf {0}\n'.format(ns.vrf)
        if ns.authentication:
            cmd = cmd + 'aaa authentication login default group {0}\n'.format(ns.aaa_grp)
        if ns.authorization:
            cmd = cmd + 'aaa authorization commands default group {0}\n'.format(ns.aaa_grp)
        if ns.accounting:
            cmd = cmd + 'aaa accounting default group {0}\n'.format(ns.aaa_grp)
        hdl.configure(cmd)

class disableTacacsPlus(object):
   """ Class to disable tacacs+ server """

   def __init__( self, hdl, log, *args ):

        arggrammar={}
        arggrammar['aaa_grp'] = '-type str -default tac1'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

        cmd = 'no aaa authentication login default group {0}\n'.format(ns.aaa_grp)
        cmd = cmd + 'no aaa authorization commands default group {0}\n'.format(ns.aaa_grp)
        cmd = cmd + 'no aaa accounting default group {0}\n'.format(ns.aaa_grp)
        hdl.configure(cmd)
        unconfigFeature(hdl, log, '-feature tacacs')


class enableRadius(object):

   """ Class to enable Radius server """

   def __init__( self, hdl, log, *args ):

        arggrammar={}
        arggrammar['radius_server'] = '-type str -required True -format {0}|{1}'.format(rex.IPv4_ADDR,rex.IPv6_ADDR)
        arggrammar['key']='-type str -required True '
        arggrammar['vrf'] = '-type str -default management -format {0}'.format(rex.VRF_NAME)
        arggrammar['rad_grp'] = '-type str -default rad1'
        arggrammar['authentication'] = '-type bool -default True'
        arggrammar['accounting'] = '-type bool -default True'
        arggrammar['auth_port'] = '-type str -default 1812'
        arggrammar['acct_port'] = '-type str -default 1813'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

        cmd = 'radius-server host {0} key {1} \n'.format(ns.radius_server,ns.key)
        cmd = cmd + 'aaa group server radius {0} \n '.format(ns.rad_grp)
        cmd = cmd + 'server {0}\n'.format(ns.radius_server)

        if ns.vrf:
            cmd = cmd + 'use-vrf {0}\n'.format(ns.vrf)
        hdl.configure(cmd)

        if ns.auth_port:
            cmd = 'radius-server host {0} auth-port {1} \n'.format(ns.radius_server,ns.auth_port)
        if ns.acct_port:
            cmd = cmd + 'radius-server host {0} acct-port {1} \n'.format(ns.radius_server,ns.acct_port)
        if ns.authentication:
            cmd = cmd + 'radius-server host {0} authentication \n'.format(ns.radius_server)
        if ns.accounting:
            cmd = cmd + 'radius-server host {0} accounting \n'.format(ns.radius_server)
        if ns.authentication:
            cmd = cmd + 'aaa authentication login default group {0}\n'.format(ns.rad_grp)
        if ns.accounting:
            cmd = cmd + 'aaa accounting default group {0}\n'.format(ns.rad_grp)
        hdl.configure(cmd)

class disableRadius(object):
   """ Class to disable Radius server """

   def __init__( self, hdl, log, *args ):

        arggrammar={}
        arggrammar['radius_server'] = '-type str -required True -format {0}|{1}'.format(rex.IPv4_ADDR,rex.IPv6_ADDR)
        arggrammar['rad_grp'] = '-type str -default rad1'

        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

        cmd = 'no aaa authentication login default group {0}\n'.format(ns.rad_grp)
        cmd = cmd + 'no aaa accounting default group {0}\n'.format(ns.rad_grp)
        cmd = cmd + 'no aaa group server radius {0}\n'.format(ns.rad_grp)
        cmd = cmd + 'no radius-server host {0}\n'.format(ns.radius_server)
        hdl.configure(cmd)

class enableLicense(object):
   ''' enabling license on DUT
       Mandatory args:
       hdl - handle of the switch
       log - harness/python logger object
       path - path of the license file
       file - license file 
       Usage:
       enableLicense(hdl,log,'-path /bootflash/lic -file lic.lic') 
   '''
   def __init__( self, hdl, log, *args):

        arggrammar={}
        arggrammar['path'] = '-default /bootflash/lic'
        arggrammar['file'] = '-default lic.lic'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)

        dir = ns.path.split('/')
        cmd = "install license {0}:{1}/{2}".format(dir[1],dir[2],ns.file)
        hdl.configure(cmd)

class disableLicense(object):
   ''' enabling license on DUT
       Mandatory args:
       hdl - handle of the switch
       log - harness/python logger object
       file - license file 
       Usage:
       enableLicense(hdl,log,'-file lic.lic') 
   '''
   def __init__( self, hdl, log, *args):

        arggrammar={}
        arggrammar['file'] = '-default lic.lic'
        ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
        self.result='pass'
        cmd="clear license {0} force".format(ns.file)
        hdl.configure(cmd)
        

######################################################################################
# Applying Qos/Network-qos/Queuing/Control-plane Policymap under Interface/system/vlan
