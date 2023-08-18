#uut1 ----- uut2 (4 connections) 
###########################################################################################
###                         TEST SCRIPT INITIALIZATION BLOCK                            ###
###########################################################################################

from ats import aetest
from ats import log
from ats.topology import exceptions
from ats.topology import Device
from ats.results import *
import subprocess
import time
from ats import topology
import tkinter
from tkinter import *
from ats.topology import *
from ats.topology import loader
from ats.log.utils import banner
from ats import tcl
import logging
import string
import os,sys
import yaml
import time
import re
import collections
#tcl.eval("package require dcos_utils")

from csccon.functions import add_state_pattern
from csccon.functions import restore_default_state_pattern
from time import gmtime, strftime
from ats.results import (Passed, Errored, Failed, Skipped,Aborted, Blocked, Passx)

# ------------------------------------------------------
# Import and initialize Genie libraries
# ------------------------------------------------------
from genie.conf import Genie
from genie.harness.standalone import run_genie_sdk, GenieStandalone
from genie.conf import Genie

tb_devices={}
global uut1_username
global uut1_pass
global uut1_mgmt

logger=logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
LOG=logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)
log=logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
from csccon import set_csccon_default, get_csccon_default
set_csccon_default('copy_sync_timeout', '2400')
set_csccon_default('sync_timeout', '2400')
set_csccon_default('exec_timeout', '2400')
set_csccon_default('config_state_timeout', '2400')

print (" End of test")

#####################################################################


############################################################################
def getList(dict):
    list = []
    for key in dict.keys():
        list.append(key)

    return list

############################################################

def check_core(router):
    """
    This function flaps the given interface on the router.
    :param router: Connection to the XR console.
    :param intf: Interface on the router.
    :returns: Passed/Failed
    """

    LOG.info('Inside check_core proc')

    pat = []
    pat = "(\d+)\s+(\d+)\s+(\d+)\s+(\w+)\s+(\d+)\s+(\d+\-\d+\-\d+)\s+(\d+\:\d+\:\d+).*"

    result = router.execute('show cores vdc-all')


    if re.search(pat, result, re.M|re.I):
       LOG.info("Core found on " + str(router))
       a = re.search(pat, result, re.M|re.I)
#       LOG.info("Core is " + str(result(0)))

       cmd = []
       cmd = 'copy core://' +  str(a.group(2)) + '/' + str(a.group(5)) +  '/' + str(a.group(3)) + ' bootflash:' + str(a.group(4)) + '_'  + str(a.group(5)) + '_' + str(a.group(6)) +  '_' + str(a.group(7))
       LOG.info("Command is  " + str(cmd))
       router.execute(cmd)

       result = router.execute('clear cores')

       return Failed

    else:
       LOG.info("Core not found on " + str(router))
       return Passed



def check_cores_andcopy(router):
    """
    This function checks core and copy core file to bootflash
    :returns: Passed/Failed
    """

    logger.info('Inside check_core proc')
    copy_path= "/auto/tftp-blr-users3/vkoganti/cores"

    pat = []
    pat = "(\d+)\s+(\d+)\s+(\d+)\s+(\w+)\s+(\d+)\s+(\d+\-\d+\-\d+)\s+(\d+\:\d+\:\d+).*"

    result = router.execute('show cores vdc-all')


    if re.search(pat, result, re.M|re.I):
       logger.info("Core found on " + str(router))
       a = re.search(pat, result, re.M|re.I)
       #logger.info("Core is " + str(result(0)))

       cmd = []
       cmd = 'copy core://' +  str(a.group(2)) + '/' + str(a.group(5)) +  '/' + str(a.group(3)) + ' bootflash:' + str(a.group(4)) + '_'  + str(a.group(5)) + '_' + str(a.group(6)) +  '_' + str(a.group(7))
       logger.info("Command is  " + str(cmd))
       router.execute(cmd)

       result = router.execute('dir bootflash: | inc %s'%str(a.group(5)))
       core_file = re.search("[0-9]+_[0-9,a-z]+_[a-z,0-9]+_log.[0-9]+.tar.gz", result)

       router.cpy("bootflash:", "scp:"+copy_path, image = core_file.group(0), vrf = 'management',\
                                               server= "10.77.143.153", user= "test", password = "test123")
       logger.error("Core found,  file %s Copied to %s"%(core_file, copy_path))

       result = router.execute('clear cores')
       return 0
    else:
       logger.info("Core not found on " + str(router))
       return 1

#########################
def check_output(router,cmd,pattern,interval=10,maxwait=90,existence='yes'):
    """
    This function checks the output of the show command
    based on the input regexp pattern and poll the command
    periodically in intervals till maxwait time is reached.
    :param router: Connection to the XR console.
    :param cmd: Show command to be executed on the DUT.
    :param pattern: Regexp pattern to match in the output.
    :param interval: Poll the command periodically using interval.
    :param maxwait: Max time till then poll the command to check output.
    :returns: Passed/Failed
    """

    LOG.info('Inside check_output proc')

    for pat in pattern:
        start = time.time()
        curr_time = 0
        result = Passed
        LOG.info("Check Pattern Match: Started polling for output: " + pat)
        while (result == Passed):

            output = router.execute(cmd)

            if (existence == 'yes'):
                if re.search(pat, output):
                    LOG.info("Check for Pattern (" + pat + ") match Passed")
                    break
            else:
               if not re.search(pat, output):
                    LOG.info("Check for Pattern (" + pat + ") no match Passed")
                    break

            LOG.info("Iteration " + str(curr_time) +  " of " + str(maxwait) + " secs..")
            LOG.info("Sleeping for " + str(interval) + " secs..")

            time.sleep(interval)
            curr_time = int(time.time() - start)
            if (curr_time > maxwait):
                LOG.error("Timeout waiting for Pattern (" + pat + ") match, returning Failed")
                return Failed
    return result
######################################################################################################
def check_yaml(dut, component):
    output = dut.execute("run bash sudo ls /bootflash/scripts/default-autocollect/ | grep " + component.lower())
    logger.info("run bash output is " + output)
    if (re.search(component.lower() + ".yaml", output)):
       logger.info(banner(component + " - Component present in default auto collect folder"))
       return Passed
    else:
       logger.error(component + " - Component not present in default auto collect folder")
       return Failed
#######################################################################################################
def verify_log_processing (dut, compname):
    output = dut.execute("show system internal event-logs auto-collect history | i i " + str(compname) + " | i i PROCESSING")
    if (re.search(compname.upper() + ".*PROCESSING",output)):
       logger.info(banner("\n%s is successfully syslog generated and it is processing"%compname))
       return Passed
    else:
       logger.error("%s not generated syslog"%compname)
       return Failed
#############################################################################################################
def verify_log_processed (dut, compname, timetogenrate = "100"):
    dut.execute("show system internal event-logs auto-collect history | i i " + str(compname) + " | i i PROCESSED") 

    pattern=[]
    pattern.append(compname.upper() + ".*PROCESSED")
    result = check_output(dut,"show system internal event-logs auto-collect history | i i " + str(compname) + " | i i PROCESSED",pattern,5,int(timetogenrate))
    if (result == Passed):
        logger.info(banner("\n%s is successfully syslog generated and it is processed"%compname))
    else:
        logger.error("%s not generated syslog"%compname)
        return Failed    

    return Passed
###########################################################################################################
def verify_log_ratelimit(dut, compname, timetogenrate = "100"):
    dut.execute("show system internal event-logs auto-collect history | i i " + str(compname) + " | i i RATELIMITED")

    pattern=[]
    pattern.append(compname.upper() + ".*RATELIMITED")
    result = check_output(dut,"show system internal event-logs auto-collect history | i i " + str(compname) + " | i i RATELIMITED",pattern,5,int(timetogenrate))
    if (result == Passed):
        logger.info(banner("\n%s is successfully syslog generated more than 1 time with 300 sec and it got ratelimited"%compname))
    else:
        logger.error("%s not generated syslog"%compname)
        return Failed

    return Passed

###########################################################################################################
def verify_log_dropped(dut, compname, timetogenrate = "100"):
    dut.execute("show system internal event-logs auto-collect history | i i " + str(compname) + " | i i DROPPED-LASTACTIONINPROG")

    pattern=[]
    pattern.append(compname.upper() + ".*DROPPED-LASTACTIONINPROG")
    result = check_output(dut,"show system internal event-logs auto-collect history | i i " + str(compname) + " | i i DROPPED-LASTACTIONINPROG",pattern,5,int(timetogenrate))
    if (result == Passed):
        logger.info(banner("\n%s is successfully syslog generated more than 1 time continuously and it got dropped"%compname))
    else:
        logger.error("%s not generated syslog"%compname)
        return Failed

    return Passed

##########################################################################################################
def verify_log_limitreached(dut, compname, timetogenrate = "20"):
    dut.execute("show system internal event-logs auto-collect history | i i " + str(compname) + " | i i EVENTLOGLIMITREACHED")

    pattern=[]
    pattern.append(compname.upper() + ".*EVENTLOGLIMITREACHED")
    result = check_output(dut,"show system internal event-logs auto-collect history | i i " + str(compname) + " | i i EVENTLOGLIMITREACHED",pattern,5,int(timetogenrate))
    if (result == Passed):
        logger.info(banner("\n%s is successfully syslog generated one by one and each syslog gap of 300 sec and it got limit reached"%compname))
    else:
        logger.error("%s not generated syslog"%compname)
        return Failed

    return Passed


############################################################################################################

def trigger_syslog(dut, compname, msg="test",matchpresent='n',match="test",timetogenrate = "300"):

    global exec_command

    output = dut.execute("run bash sudo ls -l /bootflash/eem_snapshots/*" + compname.upper() + "*")
    logger.info("eem_snapshots output is before deletion " + output)
    output = dut.execute("run bash sudo rm /bootflash/eem_snapshots/* ; ls -l /bootflash/eem_snapshots/")
    output = dut.execute("run bash sudo rm /tmp/eem_autocollect_syslog_history")   
    time.sleep(5)

    if matchpresent == 'n': 
       output = dut.execute("run bash sudo syslog_gen --comp_name " + str(compname) + " --msg " + msg + " --generate")
    else:
       output = dut.execute("run bash sudo syslog_gen --comp_name " + str(compname) + " --msg " + msg + " --text " + str(match) + " --generate")

    time.sleep(5)

    if verify_log_processing(dut,compname) == Passed:
       logger.info(compname + " being processing")
    else:
       logger.error(compname + " processing not started as expected") 
       return Failed

    if verify_log_processed(dut,compname) == Passed:
       logger.info(compname + " processed done")
    else:
       logger.error(compname + " not processed as expected")
       return Failed
    
    output = dut.execute("run bash sudo ls -l /bootflash/eem_snapshots/*" + compname.upper() + "*")
    logger.info("eem_snapshots output is after processed " + output)
    
    pattern=[]
    pattern.append(compname.upper() + ".*eem_snapshot.tar.gz")
    result = check_output(dut,"run bash sudo ls -l /bootflash/eem_snapshots/*" + compname.upper() + "*",pattern,5,int(timetogenrate))
    if (result == Passed):
        logger.info(banner("\n%s snapshot file generated successfully"%compname))
    else:
        logger.error("%s snapshot file not generated"%compname)
        return Failed        
   
    output = dut.execute("run bash sudo ls /bootflash/eem_snapshots/*" + compname.upper() + "*eem_snapshot.tar.gz ")
    logger.info(banner("\ntar the eem_snapshot file and checking the exec commands based on the component input" + output))
    if re.search(compname.upper() + ".*eem_snapshot.tar.gz", output):
       logger.info("found the component tar file")
    else:
       logger.error("not found the component tar file")
       return Failed
  
    output = dut.execute("run bash cd /bootflash/eem_snapshots/ ; tar -xvf  " + output)
    logger.info(banner("\nUntar the eem_snapshot file and checking the exec commands based on the component input" + output))

    output = dut.execute("run bash sudo ls -l /bootflash/eem_snapshots/*exec_cmds_file.txt")
    logger.info(banner("\nexec command file is " + output))
    if re.search("exec_cmds_file.txt", output):
       logger.info("found the component exec file")
    else:
       logger.error("not found the component exec file")
       return Failed

    output = dut.execute("run bash sudo cat /bootflash/eem_snapshots/*exec_cmds_file.txt")
    exec_command = output

    logger.info(banner("\nexecuted commands based yaml input " + output))
    return Passed

########################################################################################################
def trigger_syslog_ratelimit(dut, compname, msg="test",timetogenrate = "100"):
    output = dut.execute("run bash sudo ls -l /bootflash/eem_snapshots/*" + compname.upper() + "*")
    logger.info("eem_snapshots output is before deletion " + output)
    output = dut.execute("run bash sudo rm /bootflash/eem_snapshots/*" + compname.upper() + "*")
    output = dut.execute("run bash sudo rm /tmp/eem_autocollect_syslog_history")
    time.sleep(5)
    output = dut.execute("run bash sudo syslog_gen --comp_name " + str(compname) + " --msg " + msg + " --generate")
    time.sleep(30)
    output = dut.execute("run bash sudo syslog_gen --comp_name " + str(compname) + " --msg " + msg + " --generate")

    if verify_log_ratelimit(dut,compname) == Passed:
       logger.info(compname + " being ratelimited")
       return Passed
    else:
       logger.error(compname + " ratelimitd not generated as expected")
       return Failed

########################################################################################################
def trigger_syslog_dropped(dut, compname, msg="test",timetogenrate = "100"):
    output = dut.execute("run bash sudo ls -l /bootflash/eem_snapshots/*" + compname.upper() + "*")
    logger.info("eem_snapshots output is before deletion " + output)
    output = dut.execute("run bash sudo rm /bootflash/eem_snapshots/*" + compname.upper() + "*")
    time.sleep(5)
    output = dut.execute("run bash sudo rm /tmp/eem_autocollect_syslog_history")
    time.sleep(5)
    output = dut.execute("run bash sudo syslog_gen --comp_name " + str(compname) + " --msg " + msg + " --generate")
    output = dut.execute("run bash sudo syslog_gen --comp_name " + str(compname) + " --msg " + msg + " --generate")

    if verify_log_dropped(dut,compname) == Passed:
       logger.info(compname + " being dropped last action")
       return Passed
    else:
       logger.error(compname + " dropped last action not generated as expected")
       return Failed


#######################################################################################################
def trigger_syslog_limitreached(dut, compname, msg="test",timetogenrate = "100"):
    output = dut.execute("run bash sudo ls -l /bootflash/eem_snapshots/*" + compname.upper() + "*")
    logger.info("eem_snapshots output is before deletion " + output)
    output = dut.execute("run bash sudo rm /bootflash/eem_snapshots/*" + compname.upper() + "*")
    time.sleep(5)
    output = dut.execute("run bash sudo rm /tmp/eem_autocollect_syslog_history")
    time.sleep(5)
    
    i = 0
    while i <= 10:
       output = dut.execute("run bash sudo syslog_gen --comp_name " + str(compname) + " --msg " + msg + " --generate")
       logger.info("300 sec wating for to generate another log")
       time.sleep(300)
        
       if verify_log_limitreached(dut,compname) == Passed:
          logger.info(compname + " being event log limit reached after " + str(int(i+1)))
          return Passed
       else:
          logger.info(compname + " event log limit not generated as expected even after " + str(int(i+1)))
        
       i += 1

    return Failed

###############Common Setup##############################################################################
class common_setup(aetest.CommonSetup):


    @aetest.subsection
    def genie_init(self, testscript, testbed, steps, component, Autocollect_yaml_file):
        """ Initialize the environment """
        
        with steps.start("Initializing the environment for Global Variables"):
            global compname
            global message
            global autocollect_yaml_file
            global exec_command

            compname = component
            message = "default"
            autocollect_yaml_file = Autocollect_yaml_file
            exec_command = ""
            if compname == "clis":
                message = "CLIS_SYSLOG_LIC_NOT_FOUND"

        with steps.start("Initializing the environment for Genie Configurable Objects"):
            # Make sure testbed is provided
            assert testbed, 'Testbed is not provided!'
            Genie.init(testbed=testbed)
            # Overwrite the pyATS testbed for Genie Testbed
            testscript.parameters["testbed"] = Genie.testbed
            # add testduts param to parameters
            testscript.parameters['test_duts'] = [dut for dut in testbed.devices.aliases if 'vpc' in dut or 'leaf' in dut]

        with steps.start("Connect to the testbed"):
            for dev in testscript.parameters['test_duts']:
                testbed.devices[dev].connect()

##################################################################################################################################
class enable_bloggered_auto_collect(aetest.Testcase):

    # the testcase itself
    @aetest.test
    def enable_bloggered_auto_collect(self, testscript, testbed, steps):
        global compname

        for dev in testscript.parameters['test_duts']:
            testbed.devices[dev].configure('bloggerd auto-collect component {} enable'.format(compname))

##################################################################################################################################
class default_auto_collect_01(aetest.Testcase):

    # the testcase itself
    @aetest.test
    def default_auto_collect_01(self, testscript, testbed, steps):
        global compname

        fail_flag = []
        fail_msgs = ''

        for dev in testscript.parameters['test_duts']:
            with steps.start(" {} for {} - checking component present in the default auto collect folder".format(compname, dev)):
                if check_yaml(testbed.devices[dev],compname) == Passed:
                    logger.info(compname + " - Component present in the default auto collect folder")
                else:
                    logger.error(compname + " - Component not present in the default auto collect folder")    
                    fail_msgs += '{} - Component not present in the default auto collect folder\n'.format(compname)
                    fail_flag.append(0)
        
        with steps.start("Final Verdict"):
            if 0 in fail_flag:
                self.failed(reason=fail_msgs)
            else:
                self.passed()

#################################################################################################################################
class default_auto_collect_02(aetest.Testcase):

    # the testcase itself
    @aetest.test
    def default_auto_collect_02(self, testscript, testbed, steps):
        global compname
        global message

        fail_flag = []
        fail_msgs = ''

        for dev in testscript.parameters['test_duts']:
            with steps.start("{} for {} - Checking ratelimiting while syslog generates more than 1 time within 300 sec in the same component".format(compname, dev)):
                if trigger_syslog_ratelimit(testbed.devices[dev],compname,message.split()[0]) == Passed:
                    logger.info(compname + " :- ratelimiting successfully verified")
                else:
                    logger.error(compname + " :- not ratelimiting successfully verified")
                    fail_msgs += '{} - :- not ratelimiting successfully verified\n'.format(compname)
                    fail_flag.append(0)
                
        with steps.start("Final Verdict"):
            if 0 in fail_flag:
                self.failed(reason=fail_msgs)
            else:
                self.passed()

##################################################################################################################################
class default_auto_collect_03(aetest.Testcase):

    # the testcase itself
    @aetest.test
    def default_auto_collect_03(self, testscript, testbed, steps):
        global compname
        global message

        fail_flag = []
        fail_msgs = ''

        for dev in testscript.parameters['test_duts']:
            with steps.start("{} for {} - Checking dropped last action while syslog generates before processed in the same component".format(compname, dev)):
                if trigger_syslog_dropped(testbed.devices[dev],compname,message.split()[0]) == Passed:
                    logger.info(compname + " - dropped last action successfully verified")
                else:
                    logger.error(compname + " - dropped last action not successfully verified")
                    fail_msgs += '{} - :- dropped last action not successfully verified\n'.format(compname)
                    fail_flag.append(0)

        with steps.start("Final Verdict"):
            if 0 in fail_flag:
                self.failed(reason=fail_msgs)
            else:
                self.passed()

##################################################################################################################################
class default_auto_collect_04(aetest.Testcase):

    # the testcase itself
    @aetest.test
    def default_auto_collect_04(self, testscript, testbed, steps):
        global compname
        global message

        fail_flag = []
        fail_msgs = ''

        for dev in testscript.parameters['test_duts']:
            with steps.start("{} for {} - Checking event limit reached while syslog generates after 300 sec processed in the same component".format(compname, dev)):
                if trigger_syslog_limitreached(testbed.devices[dev],compname,message.split()[0]) == Passed:
                    logger.info(compname + " - eventlimitreached successfully verified")
                else:
                    logger.error(compname + " - eventlimitreached not successfully verified")
                    fail_msgs += '{} - :- eventlimitreached not successfully verified\n'.format(compname)
                    fail_flag.append(0)

        with steps.start("Final Verdict"):
            if 0 in fail_flag:
                self.failed(reason=fail_msgs)
            else:
                self.passed()

###################################################################################################################################
class default_auto_collect_05(aetest.Testcase):

    # the testcase itself
    @aetest.test
    def default_auto_collect_05(self, testscript, testbed, steps):
        global compname
        global message
        global autocollect_yaml_file
        global exec_command

        fail_flag = []
        fail_msgs = ''

        for dev in testscript.parameters['test_duts']:
            with steps.start("Iteration for Device {}".format(dev)):
                ### Read data from yaml
                with open(autocollect_yaml_file, 'r') as stream:
                    try:
                        parsed_yaml=yaml.safe_load(stream)
                        logger.info("Component YAML file exists and read properly")
                        logger.info("Parsed yaml is " + str(parsed_yaml))
                    except yaml.YAMLError as exc:
                        fail_flag.append(0)
                        fail_msgs += 'For {} - Component YAML file doesnt exists in the path {}\n'.format(dev, autocollect_yaml_file)
                        continue

                message_list = getList(parsed_yaml['components'][compname])

                for msg in message_list:
                    try:
                        message = getList(parsed_yaml['components'][compname][msg])
                        logger.info(banner("Message under  " + str(msg) + " is " + str(message)))
                    except:
                        message = ""
                        logger.info(banner("No message under " + str(msg)))
                        continue
                    
                    ### if match present
                    if re.search("match", str(message)):
                        logger.info("Match found for message " + str(msg) + " ===== " + str(parsed_yaml['components'][compname][msg]['match']))
                        if trigger_syslog(testbed.devices[dev],compname,msg,'str(y)',str(parsed_yaml['components'][compname][msg]['match'])) == Passed:
                            logger.info(compname + " - Component specific " + str(msg) + " request processed and generated snapshot file successfully")
                        else:
                            fail_flag.append(0)
                            fail_msgs += 'For {} - Component specific {} request not processed and generated snapshot file successfully\n'.format(compname, msg)
                            break
                    ### if match doesnt exists
                    else:
                        logger.info("Match not found for message " + str(msg))
                        if trigger_syslog(testbed.devices[dev],compname,msg,'str(n)') == Passed:
                            logger.info(compname + " - Component specific " + str(msg) + " request processed and generated snapshot file successfully")
                        else:
                            fail_flag.append(0)
                            fail_msgs += 'For {} - Component specific {} request not processed and generated snapshot file successfully\n'.format(compname, msg)
                            break

                    ### Verify command list executed as per yaml file
                    logger.info(banner("Executed commands are " + str(exec_command)))

                    if re.search("commands", str(message)):
                        logger.info("Command found for message " + str(msg) + " ===== " + str(parsed_yaml['components'][compname][msg]['commands']))
                        for cmd in parsed_yaml['components'][compname][msg]['commands'].split(";"):
                            cmd = cmd.strip()
                            logger.info("Command from yaml file is \"" + cmd + "\"")
                            if re.search(cmd,exec_command):
                                logger.info("Command \"" + str(cmd) + "\" exists in exec command list")
                            else:
                                fail_flag.append(0)
                                fail_msgs += 'Command {} does not exists in exec command list\n'.format(cmd)
                                break
                    else:
                        logger.info("Command not found for message " + str(msg))

                    ### Verify show tech list executed as per yaml file
                    logger.info(banner("Executed commands are " + str(exec_command)))

                    if re.search("tech-sup", str(message)):
                        logger.info("Tech-support found for message " + str(msg) + " ===== " + str(parsed_yaml['components'][compname][msg]['tech-sup']))
                        for cmd in parsed_yaml['components'][compname][msg]['tech-sup'].split(";"):
                            cmd = cmd.strip()
                            logger.info("Tech support Command from yaml file is \"" + cmd + "\"")
                            if re.search("show.*tech.*" + cmd,exec_command):
                                logger.info("Tech support Command \"" + str(cmd) + "\" exists in exec command list")
                            else:
                                fail_flag.append(0)
                                fail_msgs += 'Tech support Command {} does not exists in exec command list\n'.format(cmd)
                                break
                    else:
                        logger.info("Tech support Command not found for message " + str(msg))

        with steps.start("Final Verdict"):
            if 0 in fail_flag:
                self.failed(reason=fail_msgs)
            else:
                self.passed()

####################################################################################################################################
class default_auto_collect_06(aetest.Testcase):

    # the testcase itself
    @aetest.test
    def default_auto_collect_06(self, testscript, testbed, steps):
        global compname
        global message

        fail_flag = []
        fail_msgs = ''
        
        for dev in testscript.parameters['test_duts']:
            with steps.start("For {} - {} - disable/enable the component and checking the yaml is present".format(dev, compname)):

                logger.info(banner("\nDisabling the the component and checking the component not present in the default collect folder"))
                testbed.devices[dev].execute("bloggerd auto-collect component " + compname + " disable")
                time.sleep(10)

                output = testbed.devices[dev].execute("run bash sudo ls /bootflash/scripts/default-autocollect/ | grep " + compname.lower())
                logger.info("run bash output is " + output)
                if not (re.search(compname.lower() + ".yaml", output)):
                    logger.info(banner(compname + " - Component not present in default auto collect folder"))
                else:
                    logger.error(compname + " - Component present in default auto collect folder")
                    fail_msgs += '{} - :-  Component present in default auto collect folder\n'.format(compname)
                    fail_flag.append(0)
                
                time.sleep(10)

                logger.info(banner("\nEnabling the the component and checking the component present in the default collect folder"))
                testbed.devices[dev].execute("bloggerd auto-collect component " + compname + " enable")
                time.sleep(10)

                if check_yaml(testbed.devices[dev],compname) == Passed:
                    logger.info(compname + " - Component present in the default auto collect folder")
                else:
                    logger.error(compname + " - Component not present in the default auto collect folder")
                    fail_msgs += '{} - :-  Component not present in the default auto collect folder\n'.format(compname)
                    fail_flag.append(0)

        with steps.start("Final Verdict"):
            if 0 in fail_flag:
                self.failed(reason=fail_msgs)
            else:
                self.passed()


# #############################################################################################3

# class common_cleanup(aetest.CommonCleanup):
#     @aetest.subsection
#     def disconn_handle(self,uut1_conn):
#         global tb_devices
#         logger.info("Starting Common Cleanup")
#         uut1_conn=tb_devices['device_handles'][0]
#         try:
#            uut1_config_result=uut1_conn.execute("run bash sudo rm /bootflash/eem_snapshots/*")           
#            uut1_config_result=uut1_conn.configure("no feature bash-shell")

#            logger.info("unconfig Successful on UUT1")

#         except Exception as err:
#             logger.error("UUT1 Cleanup Failed")
#             logger.error("Error while common cleaup: " + str(err) + "on routers")
#             self.failed(goto=['exit'])
		
#         try:
#             uut1_conn.disconnect()
#         except Exception as e:
#             log.error("Discconection from UUT1 failed")
#             self.failed(goto=['exit'])
