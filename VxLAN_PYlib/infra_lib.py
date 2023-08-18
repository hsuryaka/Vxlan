import re
import time
import logging
import json
import random
from pyats.async_ import pcall

import unicon.statemachine.statemachine
from unicon.eal.dialogs import Statement, Dialog

from pyats.aereport.utils.argsvalidator import ArgsValidator
ArgVal = ArgsValidator()

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# ====================================================================================================#
# Infra Level Configures
# ====================================================================================================#
class infraConfigure:
    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def configureVerifyFeature(deviceList, featureList):
        featureStatus   = []
        featureMsgs     = "\n"

        if type(featureList) is not list:
            featureList = [featureList]
        if type(deviceList) is not list:
            deviceList = [deviceList]

        for device in deviceList:
            featureMsgs += "\n\nFor " + str(device.alias) + "\n"
            featureMsgs += "====================================\n\n"
            for feature in featureList:
                device.configure("feature " + str(feature),timeout = 300)
                if ("enabled" in device.execute("sh feature | grep '" + str(feature) + "'")) \
                        or (str(feature) in device.execute("sh run | grep 'feature " + str(feature) + "'")):
                    featureMsgs += "PASS : Enabling feature " + str(feature) + " is Successful\n"
                    featureStatus.append(1)
                else:
                    featureMsgs += "FAIL : Enabling feature " + str(feature) + " has Failed\n"
                    featureStatus.append(0)

        if 0 in featureStatus:
            return {'result' : 0, 'log' : featureMsgs}
        else:
            return {'result' : 1 , 'log': featureMsgs}

    # ====================================================================================================#
    @staticmethod
    def configureVerifyFeatureSet(deviceList, featureSetList):
        featureStatus   = []
        featureMsgs     = "\n"

        if type(featureSetList) is not list:
            featureSetList = [featureSetList]
        if type(deviceList) is not list:
            deviceList = [deviceList]

        for device in deviceList:
            featureMsgs += "\n\nFor " + str(device.alias) + "\n"
            featureMsgs += "====================================\n\n"
            for feature in featureSetList:
                device.configure("install feature-set " + str(feature),timeout = 300)
                device.configure("feature-set " + str(feature), timeout=300)
                if re.search(">enabled|>installed", device.execute("sh feature-set " + str(feature) + " | xml | i i cfcFeatureSetOpStatus>")) \
                        and (str(feature) in device.execute("sh feature-set | grep '" + str(feature) + "'")):
                    featureMsgs += "PASS : Installing feature-set" + str(feature) + "is Successful"
                    featureStatus.append(1)
                else:
                    featureMsgs += "FAIL : Installing feature-set" + str(feature) + "has Failed"
                    featureStatus.append(0)

        if 0 in featureStatus:
            return {'result' : 0, 'log' : featureMsgs}
        else:
            return {'result' : 1 , 'log': featureMsgs}

# ====================================================================================================#
# Infra Level Triggers
# ====================================================================================================#
class infraEORTrigger:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def verifyModuleReload(args_dict):

        # Define Arguments Definition
        args_def = [
            ('dut'                          , 'm', 'any'),
            ('mod_num'                      , 'm', [str,int]),
            ('exclude_log_check_pattern'    , 'o', [str])
        ]

        help_string = """
        ==================================================================================================================================

           Proc Name           : verifyModuleReload

           Functionality       : Reload the Module of an EOR 
                                 Method waits for 330 sec for module to come UP
                                 Checks for any error logs as part of it

           Parameters          : A dictionary with below key_value pairs.

           Name                         Required       Description                 Default Value
           ====                         ==========      ===========                 =============
           dut                          :   M   :     EOR Device handle              : N/A
           mod_num                      :   M   :   Module number to be reloaded     : N/A
           exclude_log_check_pattern    :   O   :   Skip patter for error log check  : N/A

           Parameter Example   :

                               ArgDict = {
                                   'dut'                        : uut1,
                                   'mod_num'                    : '1',
                                   'exclude_log_check_pattern'  : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED'
                               }

            Return Value        : {'status' : 0/1, 'logs': 'any logs captured'}

        ==================================================================================================================================
        """

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            # Raise exception if wrong and give help-string
            log.info("Exception seen:" + str(e))
            log.info(help_string)
            return 0

        # Setting UP few variables
        dev_uut         = args_dict['dut']
        module          = args_dict['mod_num']
        validation_msgs = ''
        fail_flag       = []
        if 'exclude_log_check_pattern' not in args_dict.keys():
            args_dict['exclude_log_check_pattern'] = ''

        # This command will reload module 4. Proceed[y/n]?  [n]
        dialog = Dialog([
            Statement(pattern=r'^.*Proceed\[y\/n\]\?  \[n\].*$',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True)
        ])

        # Getting few basic details
        dev_uut.execute("show mod " + str(module) + " | no")
        dev_uut.execute("slot " + str(module)+" show hard int ver | no")
        dev_uut.execute("sh ver | i i 'NXOS' | no")

        module_status_table = json.loads(dev_uut.execute("show mod "+str(module)+" | json | beg '{'"))
        module_status = module_status_table['TABLE_modinfo']['ROW_modinfo']['status']

        # Check if the module is in OK state for proceeding to reload
        if ('ok' in module_status) or ('active' in module_status) or ('standby' in module_status):

            # Setup the console logging
            dev_uut.configure('''
                logging console 6
                logging module 6
            ''')

            # Clear the logfile for capturing logs for LC Reload Trigger
            dev_uut.configure("clear logging logfile")

            # Since the module status is 'ok|active|standby', continue with Reload
            log.info("Module "+str(module)+" status is in 'ok|active|standby' state, continue with the Reload of the module")
            print("Module " + str(module) + " status is in 'ok|active|standby' state, continue with the Reload of the module")

            # Perform LC Reload anc wait for 30sec
            dev_uut.configure('reload mod '+str(module), reply=dialog, timeout=300)
            time.sleep(30)

            # Enter into an infinite Loop to poll the module status
            iteration_counter = 1
            while 1:
                # Tweak to get only json output among multiple console log dump
                out = dev_uut.execute("show mod " + str(module) + " | json | beg '{'").split('\n')
                for i in range(len(out)):
                    if 'TABLE_modinfo' in out[i]:
                        module_status_table = json.loads(out[i])
                        module_status = module_status_table['TABLE_modinfo']['ROW_modinfo']['status']

                if ('ok' in module_status) or ('active' in module_status) or ('standby' in module_status):
                    log.info("Module "+str(module)+" came UP to 'ok|active|standby' state")
                    print("Module " + str(module) + " came UP to 'ok|active|standby' state")
                    break
                else:
                    log.info("Module "+str(module)+" is not in 'ok|active|standby' state, waiting for 10 sec")
                    print("Module " + str(module) + " is not in 'ok|active|standby' state, waiting for 10 sec")
                    if iteration_counter < 60:
                        time.sleep(10)
                    else:
                        log.info("Module " + str(module) + " is not in 'ok|active|standby' state, even after waiting for 300 sec")
                        print("Module " + str(module) + " is not in 'ok|active|standby' state, even after waiting for 300 sec")
                        fail_flag.append(0)
                        break
                iteration_counter+=1

            # Reset back the console logging
            dev_uut.configure('''
                logging console 3
                logging module 3
            ''')

            # Check for error logs occured
            error_pattern = 'CRASHED|failed|CPU Hog|malloc|core dump|mts_send|redzone|error'
            skip_pattern = str(args_dict['exclude_log_check_pattern'])
            if skip_pattern != '':
                device_error_logs_dump = dev_uut.execute("show logg logf | egr ig '"+str(error_pattern)+"' | ex ig '"+str(skip_pattern)+"'")
            else:
                device_error_logs_dump = dev_uut.execute("show logg logf | egr ig '" + str(error_pattern)+"'")
            if device_error_logs_dump != '':
                device_error_log_lst = device_error_logs_dump.split('\n')
                dev_uut.configure("clear logging logfile")
                if len(device_error_log_lst) > 0:
                    validation_msgs += "\n\n\nError logs found - count : "+\
                                        str(len(device_error_log_lst))+\
                                        " :\n================================\n\n"+\
                                        str(device_error_logs_dump)+"\n\n"
                    fail_flag.append(0)
            else:
                validation_msgs += "\nNo Error Logs seen\n"
        else:
            # Module is not in 'ok|active|standby' state, so cannot continue with LC Reload
            fail_flag.append(0)
            validation_msgs += ("Module "+str(module)+" status is not in 'ok|active|standby' state, cannot continue with the Reload of the module")
            log.info("Module "+str(module)+" status is not in 'ok|active|standby' state, cannot continue with the Reload of the module")
            print("Module " + str(module) + " status is not in 'ok|active|standby' state, cannot continue with the Reload of the module")

        # Check the fail_flag and report accordingly
        if 0 in fail_flag:
            return {'status': 0, 'logs': validation_msgs}
        else:
            return {'status': 1, 'logs': validation_msgs}

    # ====================================================================================================#
    @staticmethod
    def verifyDeviceSSO(args_dict):

        # Define Arguments Definition
        args_def = [
            ('dut'                          , 'm', 'any'),
        ]

        help_string = """
        ==================================================================================================================================

           Proc Name           : verifyDeviceSSO

           Functionality       : Performs SSO on an EOR chassis 
                                 Checks for any error logs as part of it

           Parameters          : A dictionary with below key_value pairs.

           Name                         Required       Description                 Default Value
           ====                         ==========      ===========                 =============
           dut                          :   M   :     EOR Device handle              : N/A

           Parameter Example   :

                               ArgDict = {
                                   'dut'                        : uut1,
                               }

            Return Value        : {'status' : 0/1, 'logs': 'logs'}

        ==================================================================================================================================
        """

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            # Raise exception if wrong and give help-string
            log.info("Exception seen:" + str(e))
            log.info(help_string)
            return 0

        # Setting UP few variables
        dev_uut         = args_dict['dut']
        validation_msgs = ''
        fail_flag       = []
        if 'exclude_log_check_pattern' not in args_dict.keys():
            args_dict['exclude_log_check_pattern'] = ''

        # Perform Sync on the HA console - blind config PASS/WARN
        sync_state_result = dev_uut.sync_state()
        if sync_state_result:
            log.info("Synchronizing the Active/Standby console state Successful")
            print("Synchronizing the Active/Standby console state Successful")
        else:
            log.info("Synchronizing the Active/Standby console state Failed")
            print("Synchronizing the Active/Standby console state Failed")

        # Verify/Get if the HA Status is HOT STANDBY on both active and standby
        active_console_HA_state = dev_uut.get_rp_state()
        standby_console_HA_state = dev_uut.get_rp_state(target='standby')

        # Continue to SSO only if the HA state is STANDBY HOT
        if 'STANDBY HOT' in active_console_HA_state and 'STANDBY HOT' in standby_console_HA_state:

            log.info("Console are in Synchronized HA STANDBY HOT state, continue to SSO")
            print("Console are in Synchronized HA STANDBY HOT state, continue to SSO")
            validation_msgs += "\nConsole are in Synchronized HA STANDBY HOT state, continue to SSO\n"

            sup_states = dev_uut.execute('show mod | i i supervisor')
            validation_msgs += "\nSupervisor states before SSO: \n" +\
                                str(sup_states)

            # Perform the SSO
            SSO_status = dev_uut.switchover(timeout=1200, sync_standby=True, prompt_recovery=True)

            if SSO_status:
                log.info("System Switchover is Successful")
                print("System Switchover is Successful")
                validation_msgs += "\n\n ==> System Switchover is Successful <== \n"
            else:
                fail_flag.append(0)
                log.info("System Switchover has Failed")
                print("System Switchover has Failed")
                validation_msgs += "\n\n ==> System Switchover is Successful <== \n"

            # Perform Sync on the HA console - blind config PASS/WARN
            sync_state_result = dev_uut.sync_state()
            if sync_state_result:
                log.info("Synchronizing the Active/Standby console state Successful")
                print("Synchronizing the Active/Standby console state Successful")
            else:
                log.info("Synchronizing the Active/Standby console state Failed")
                print("Synchronizing the Active/Standby console state Failed")

            sup_states = dev_uut.execute('show mod | i i supervisor')
            validation_msgs += "\nSupervisor states after SSO: \n" +\
                                str(sup_states)

            # Clear the logfile for capturing logs for LC Reload Trigger
            dev_uut.configure("clear logging logfile")

            # Check for error logs occured
            error_pattern = 'CRASHED|failed|CPU Hog|malloc|core dump|mts_send|redzone|error'
            skip_pattern = str(args_dict['exclude_log_check_pattern'])
            if skip_pattern != '':
                device_error_logs_dump = dev_uut.execute("show logg logf | egr ig '"+str(error_pattern)+"' | ex ig '"+str(skip_pattern)+"'")
            else:
                device_error_logs_dump = dev_uut.execute("show logg logf | egr ig '" + str(error_pattern)+"'")
            if device_error_logs_dump != '':
                device_error_log_lst = device_error_logs_dump.split('\n')
                dev_uut.configure("clear logging logfile")
                if len(device_error_log_lst) > 0:
                    validation_msgs += "\n\n\nError logs found - count : "+\
                                        str(len(device_error_log_lst))+\
                                        " :\n================================\n\n"+\
                                        str(device_error_logs_dump)+"\n\n"
                    fail_flag.append(0)
            else:
                validation_msgs += "\n\nNo Error Logs seen\n"

        else:
            fail_flag.append(0)
            log.info("Console are not in Synchronized HA STANDBY HOT state, cannot perform SSO")
            print("Console are not in Synchronized HA STANDBY HOT state, cannot perform SSO")
            validation_msgs += "\nConsole are in Synchronized HA STANDBY HOT state, continue to SSO\n"

        # Check the fail_flag and report accordingly
        if 0 in fail_flag:
            return {'status': 0, 'logs': validation_msgs}
        else:
            return {'status': 1, 'logs': validation_msgs}

# ====================================================================================================#
# Infra Level Triggers
# ====================================================================================================#
class infraTrigger:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def verifyProcessRestart(dut, p_name):
        unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
        unicon_state.add_state_pattern(pattern_list="r'bash-*$'")

        post_kill_pid   = ""
        pid             = ""

        dut.configure("feature bash-shell")

        # Get the PID of the process before killing it
        pid_data = dut.execute("show system internal sysmgr service name " + str(p_name) + " | i i PID")
        pid_regex = re.search("PID = (\\d+)", pid_data, re.I)
        if pid_regex is not 0:
            pid = pid_regex.group(1)

        # Kill the process in bash prompt
        dut.execute("run bash", allow_state_change="True")
        dut.execute("sudo su", allow_state_change="True")
        dut.execute("kill -9 " + str(pid), allow_state_change="True")
        dut.execute("exit", allow_state_change="True")
        dut.execute("exit", allow_state_change="True")

        unicon_state.restore_state_pattern()
        time.sleep(30)

        # Get the PID of the process after killing it
        post_kill_pid_data = dut.execute("show system internal sysmgr service name " + str(p_name) + " | i i PID")
        post_kill_pid_regex = re.search("PID = (\\d+)", post_kill_pid_data, re.I)
        if post_kill_pid_regex is not 0:
            post_kill_pid = post_kill_pid_regex.group(1)

        # Check if pre-kill PID and post-kill PID are different
        if pid != post_kill_pid:
            return 1
        else:
            return 0

    # ====================================================================================================#
    @staticmethod
    def switchReload(uut):
        dialog = Dialog([
            Statement(pattern=r'.*Do you wish to proceed anyway.*',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True)
        ])

        uut.configure("copy r s", timeout=1200)

        result = uut.reload(reload_command="reload", prompt_recovery=True, dialog=dialog, timeout=1200, config_lock_retries=10, config_lock_retry_sleep=20)

        if result:
            log.info('Reload successful -- Waiting 180 seconds for config sync')
            time.sleep(180)
            return 1
        else:
            log.info('Reload Failed')
            return 0

    # ====================================================================================================#
    @staticmethod
    def switchASCIIreload(uut):
        dialog = Dialog([
            Statement(pattern=r'.*Do you wish to proceed anyway.*',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True)
        ])

        uut.configure("copy r s", timeout=1200)

        result = uut.reload(reload_command="reload ascii", prompt_recovery=True, dialog=dialog, timeout=1200, config_lock_retries=10, config_lock_retry_sleep=20)

        if result:
            log.info('Reload successful -- Waiting 180 seconds for config sync')
            time.sleep(180)
            return 1
        else:
            log.info('Reload Failed')
            return 0

# ====================================================================================================#
# Infra Level Verifications
# ====================================================================================================#
class infraVerify:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def getModuleFromInt(dut, interfs):
        log.info("Inside getModuleFromInts")
        module_list = []
        # Check type of interface
        for interf in interfs:
            print("checking interface "+str(interf))
            if re.search('Po', interf, re.I):
                print("interface is a PO - processing ...")
                po_summ_json = json.loads(dut.execute("show port-cha summary interf " + str(interf) + " | json"))
                po_member_json = po_summ_json['TABLE_channel']['ROW_channel']['TABLE_member']['ROW_member']
                if type(po_member_json) == list:
                    log.info("Inside list type")
                    for int_json in po_member_json:
                        main_interface = re.sub('[Eethrn]','',int_json['port'])
                        log.info("main_interface "+str(main_interface))
                        if main_interface.split('/')[0] not in module_list:
                            module_list.append(main_interface.split('/')[0])
                if type(po_member_json) == dict:
                    log.info("Inside dict type")
                    main_interface = re.sub('[Eethrn]','',po_member_json['port'])
                    log.info("main_interface " + str(main_interface))
                    if main_interface.split('/')[0] not in module_list:
                        module_list.append(main_interface.split('/')[0])
            elif re.search('Eth', interf, re.I):
                print("interface is a Ethernet - processing ...")
                interface = interf.split('/')[0]
                intf_parse = re.match('(ethernet|eth)(\\d+)',interface,re.I)
                if intf_parse:
                    if intf_parse.group(2) not in module_list:
                        module_list.append(intf_parse.group(2))
        log.info(module_list)
        return module_list

    # ====================================================================================================#
    @staticmethod
    def verifyVPCStatus(peer1, peer2):
        peer1VPCStatus = []
        peer2VPCStatus = []
        peer1VPCmsgs = "For PEER-1\n==========\n"
        peer2VPCmsgs = "For PEER-2\n==========\n"
        vpc_ids = []

        peer_1_vpc_xml_data = peer1.execute("show vpc brief | xml")
        peer_2_vpc_xml_data = peer2.execute("show vpc brief | xml")

        # =============================================================================================================================#
        # Verify the peer-keep-alive status for peer-1
        if "<vpc-peer-keepalive-status>peer-alive<" in peer_1_vpc_xml_data:
            peer1VPCStatus.append(0)
            peer1VPCmsgs += "PASS : Peer keep alive status for " + str(peer1.alias) + " is OK \n"
        else:
            peer1VPCStatus.append(1)
            peer1VPCmsgs += "FAIL : Peer keep alive status for " + str(peer1.alias) + " is not OK \n"

        # Verify the peer-keep-alive status for peer-2
        if "<vpc-peer-keepalive-status>peer-alive<" in peer_2_vpc_xml_data:
            peer2VPCStatus.append(0)
            peer2VPCmsgs += "PASS : Peer keep alive status for " + str(peer2.alias) + " is OK \n"
        else:
            peer2VPCStatus.append(1)
            peer2VPCmsgs += "FAIL : Peer keep alive status for " + str(peer2.alias) + " is not OK \n"

        # =============================================================================================================================#
        # Verify the peer status for peer-1
        if "<vpc-peer-status>peer-ok<" in peer_1_vpc_xml_data:
            peer1VPCStatus.append(0)
            peer1VPCmsgs += "PASS : Peer Adjacency Status from " + str(peer1.alias) + " is formed OK \n"
        else:
            peer1VPCStatus.append(1)
            peer1VPCmsgs += "FAIL : Peer Adjacency Status from " + str(peer1.alias) + " is not formed \n"

        # Verify the peer status for peer-2
        if "<vpc-peer-status>peer-ok<" in peer_2_vpc_xml_data:
            peer2VPCStatus.append(0)
            peer2VPCmsgs += "PASS : Peer Adjacency Status from " + str(peer2.alias) + " is formed OK \n"
        else:
            peer2VPCStatus.append(1)
            peer2VPCmsgs += "FAIL : Peer Adjacency Status from " + str(peer2.alias) + " is not formed \n"

        # =============================================================================================================================#
        # Verify the peer link status for peer-1
        if "<peer-link-port-state>1<" in peer_1_vpc_xml_data:
            peer1VPCStatus.append(0)
            peer1VPCmsgs += "PASS : Peer Link Status from " + str(peer1.alias) + " is UP \n"
        else:
            peer1VPCStatus.append(1)
            peer1VPCmsgs += "FAIL : Peer Link Status from " + str(peer1.alias) + " is not UP \n"

        # Verify the peer link status for peer-2
        if "<peer-link-port-state>1<" in peer_2_vpc_xml_data:
            peer2VPCStatus.append(0)
            peer2VPCmsgs += "PASS : Peer Link Status from " + str(peer2.alias) + " is UP \n"
        else:
            peer2VPCStatus.append(1)
            peer2VPCmsgs += "FAIL : Peer Link Status from " + str(peer2.alias) + " is not UP \n"

        # =============================================================================================================================#
        # Get VPC IDs
        vpc_ids_data = peer1.execute("show vpc brief | xml | grep '<vpc-id>'")
        if vpc_ids_data  != '':
            vpc_ids_data = vpc_ids_data.split("\n")
            for entry in vpc_ids_data:
                vpc_ids_regex = re.search("<vpc-id>(\\d+)<", entry, re.I)
                if vpc_ids_regex is not 0:
                    vpc_ids.append(vpc_ids_regex.group(1))

            peer1VPCmsgs += "VPC ID's configured are :"
            peer1VPCmsgs += str(vpc_ids)

            peer2VPCmsgs += "VPC ID's configured are :"
            peer2VPCmsgs += str(vpc_ids)

            peer1VPCmsgs += "\n"
            peer2VPCmsgs += "\n"

            # Verify VPC Status on peer-1
            for vpc_id in vpc_ids:
                _indi_vpc_status_data = peer1.execute("show vpc " + str(vpc_id) + " | xml")

                if "<vpc-port-state>1<" in _indi_vpc_status_data:
                    peer1VPCmsgs += "\t\tPASS : VPC ID - '" + str(vpc_id) + "' is UP\n"
                    peer1VPCStatus.append(0)
                else:
                    peer1VPCmsgs += "\t\tFAIL : VPC ID - '" + str(vpc_id) + "' is not UP\n"
                    peer1VPCStatus.append(1)

            # Verify VPC Status on peer-2
            for vpc_id in vpc_ids:
                _indi_vpc_status_data = peer2.execute("show vpc " + str(vpc_id) + " | xml")

                if "<vpc-port-state>1<" in _indi_vpc_status_data:
                    peer2VPCmsgs += "\t\tPASS : VPC ID - '" + str(vpc_id) + "' is UP\n"
                    peer2VPCStatus.append(0)
                else:
                    peer2VPCmsgs += "\t\tFAIL : VPC ID - '" + str(vpc_id) + "' is not UP\n"
                    peer2VPCStatus.append(1)

        if 1 in peer1VPCStatus or 1 in peer2VPCStatus:
            return {'result' : 0, 'log' : str(peer1VPCmsgs) + str(peer2VPCmsgs)}
        else:
            return {'result' : 1 , 'log': str(peer1VPCmsgs) + str(peer2VPCmsgs)}

    # ====================================================================================================#
    def verifyBasicVxLANCC(self, args_dict):

        # Define Arguments Definition
        args_def = [
            ('dut'                  , 'M', 'any'),
            ('fnl_flag'             , 'o', [str, int]),
            ('random_vlan'          , 'o', [str, int]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print("Exception seen:" + str(e))
            log.info("Exception seen:" + str(e))
            return 0

        if 'fnl_flag' not in args_dict.keys():
            args_dict['fnl_flag'] = 0
        if 'random_vlan' not in args_dict.keys():
            args_dict['random_vlan'] = 0

        # Method global variables
        fail_flag = []
        module_nums = []
        validation_msgs = ''

        # Verify VxLAN Config-check CC
        vxlan_config_check_cc = json.loads(args_dict['dut'].execute("show consistency-checker vxlan config-check detail | no", timeout=1200))
        if type(vxlan_config_check_cc['result']['checkers']) is list:
            for cc_check in vxlan_config_check_cc['result']['checkers']:
                if "NOT_OK" in cc_check['status']:
                    validation_msgs += '\nFAIL - '+str(cc_check['type'])
                    fail_flag.append(0)
                else:
                    validation_msgs += '\nPASS - '+str(cc_check['type'])

        # Verify VxLAN infra CC
        vxlan_infra_cc = json.loads(args_dict['dut'].execute("show consistency-checker vxlan infra detail | no", timeout=1200))
        if type(vxlan_infra_cc['result']['checkers']) is list:
            for cc_check in vxlan_infra_cc['result']['checkers']:
                if "NOT_OK" in cc_check['status']:
                    validation_msgs += '\nFAIL - '+str(cc_check['type'])
                    fail_flag.append(0)
                else:
                    validation_msgs += '\nPASS - '+str(cc_check['type'])

        # Verify VxLAN vlan CC
        test_vlan = ''
        if int(args_dict['fnl_flag']):
            validation_msgs += '\nSKIP - CC_TYPE_VXLAN_VLAN - FnL Flag enabled'
        else:
            if int(args_dict['random_vlan']):
                vniVlans = args_dict['dut'].execute("sh nve vni | i i l2", timeout=100).split('\n')
                test_vlan_raw = vniVlans[random.randint(0,len(vniVlans)-2)]
                if test_vlan_raw != '':
                    _re_test_vlan = re.search('L2 \[(\d+)\]', test_vlan_raw, re.I)
                    if _re_test_vlan:
                        test_vlan = _re_test_vlan.groups(0)[0]
                if test_vlan != '':
                    vxlan_vlan_cc = json.loads(args_dict['dut'].execute("show consistency-checker vxlan vlan "+str(test_vlan)+" detail | no", timeout=1200))
                    if type(vxlan_vlan_cc['result']['checkers']) is list:
                        for cc_check in vxlan_vlan_cc['result']['checkers']:
                            if "NOT_OK" in cc_check['status']:
                                validation_msgs += '\nFAIL - '+str(cc_check['type'])
                                fail_flag.append(0)
                            else:
                                validation_msgs += '\nPASS - '+str(cc_check['type'])
                else:
                    validation_msgs += '\nSKIP - CC_TYPE_VXLAN_VLAN - Could not parse VNI VLAN'
            else:
                vxlan_vlan_cc = json.loads(args_dict['dut'].execute("show consistency-checker vxlan vlan all detail | no", timeout=1200))
                if type(vxlan_vlan_cc['result']['checkers']) is list:
                    for cc_check in vxlan_vlan_cc['result']['checkers']:
                        if "NOT_OK" in cc_check['status']:
                            validation_msgs += '\nFAIL - '+str(cc_check['type'])
                            fail_flag.append(0)
                        else:
                            validation_msgs += '\nPASS - '+str(cc_check['type'])

        # Verify VxLAN l2 mac CC
        mac_learnt_ints = []
        l2_mac_nve_out = args_dict['dut'].execute("sh nve vni | i i l2 | head line 1")
        l2_mac_nve_data = l2_mac_nve_out.split(" ")
        while "" in l2_mac_nve_data:
            l2_mac_nve_data.remove("")
        l2vni = l2_mac_nve_data[1]
        if args_dict['dut'].execute("sh mac add dyn vni "+str(l2vni)+" | json") != '':
            l2_vni_mac_json = json.loads(args_dict['dut'].execute("sh mac add dyn vni "+str(l2vni)+" | json"))
            mac_addresses = l2_vni_mac_json['TABLE_mac_address']['ROW_mac_address']

            if type(mac_addresses) == list:
                for mac_item in mac_addresses:
                    if (mac_item['disp_port'] not in mac_learnt_ints) and (re.search('Eth|po', mac_item['disp_port'], re.I)):
                        mac = mac_item['disp_mac_addr']
                        mac_learnt_ints.append(mac_item['disp_port'])

            elif type(mac_addresses) == dict:
                mac = mac_addresses['disp_mac_addr']
                disp_port = l2_vni_mac_json['TABLE_mac_address']['ROW_mac_address']['disp_port']
                if (disp_port not in mac_learnt_ints) and (re.search('Eth|po', disp_port, re.I)):
                    mac_learnt_ints.append(mac)

            log.info(mac_learnt_ints)
            if mac_learnt_ints:
                module_nums = self.getModuleFromInt(args_dict['dut'], mac_learnt_ints)
            if module_nums:
                for mod_num in module_nums:
                    vxlan_l2_mac_cc = json.loads(args_dict['dut'].execute("sh consistency-checker vxlan l2 mac-address "+str(mac)+" mod "+str(mod_num)+" detail | no", timeout=1200))
                    if type(vxlan_l2_mac_cc['result']['checkers']) is list:
                        for cc_check in vxlan_l2_mac_cc['result']['checkers']:
                            if "NOT_OK" in cc_check['status']:
                                validation_msgs += '\nFAIL - Module - '+str(mod_num)+' - '+str(cc_check['type'])
                                fail_flag.append(0)
                            else:
                                validation_msgs += '\nPASS - Module - '+str(mod_num)+' - '+str(cc_check['type'])

        # Verify VxLAN l2 module CC
        if module_nums:
            for mod_num in module_nums:
                vxlan_l2_cc = json.loads(args_dict['dut'].execute("show consistency-checker vxlan l2 module "+str(mod_num)+" detail | no", timeout=1200))
                if type(vxlan_l2_cc['result']['checkers']) is list:
                    for cc_check in vxlan_l2_cc['result']['checkers']:
                        if "NOT_OK" in cc_check['status']:
                            validation_msgs += '\nFAIL - Module - '+str(mod_num)+' - '+str(cc_check['type'])
                            fail_flag.append(0)
                        else:
                            validation_msgs += '\nPASS - Module - '+str(mod_num)+' - '+str(cc_check['type'])

        # Verify VxLAN l3 vrf all
        vxlan_l3_vrf_all_start_scan = args_dict['dut'].execute("show consistency-checker vxlan l3 vrf all start-scan", timeout=600)
        time.sleep(120)
        args_dict['dut'].execute("show consistency-checker vxlan l3 vrf all report | no", timeout=600)
        vxlan_l3_vrf_all_report_v4 = args_dict['dut'].execute("show consistency-checker vxlan l3 vrf all report | beg i 'IPv4' | i i 'IPv4|Consistency-checker' | head line 2", timeout=1200)
        if 'FAIL' in vxlan_l3_vrf_all_report_v4:
            validation_msgs += '\nFAIL - CC_TYPE_L3_VRF_ALL_IPv4'
            fail_flag.append(0)
        else:
            validation_msgs += '\nPASS - CC_TYPE_L3_VRF_ALL_IPv4'
        vxlan_l3_vrf_all_report_v6 = args_dict['dut'].execute("show consistency-checker vxlan l3 vrf all report | beg i 'IPv6' | i i 'IPv6|Consistency-checker' | head line 2", timeout=1200)
        if 'FAIL' in vxlan_l3_vrf_all_report_v6:
            validation_msgs += '\nFAIL - CC_TYPE_L3_VRF_ALL_IPv6'
            fail_flag.append(0)
        else:
            validation_msgs += '\nPASS - CC_TYPE_L3_VRF_ALL_IPv6'

        if 0 in fail_flag:
            return {'status':0, 'logs':validation_msgs}
        else:
            return {'status': 1, 'logs': validation_msgs}

    # ====================================================================================================#
    def system_ERR_CORES_CC_Check(self, dut, args_dict):

        # Define Arguments Definition
        args_def = [
            ('dut_list'                     , 'o', [list]),
            ('cc_check'                     , 'o', [str, int]),
            ('cores_check'                  , 'o', [str, int]),
            ('logs_check'                   , 'o', [str, int]),
            ('exclude_log_check_pattern'    , 'o', [str, int]),
            ('fnl_flag'                     , 'o', [str, int]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print("Exception seen:" + str(e))
            log.info("Exception seen:" + str(e))
            return 0

        if 'cc_check' not in args_dict.keys():
            args_dict['cc_check'] = 1
        if 'cores_check' not in args_dict.keys():
            args_dict['cores_check'] = 1
        if 'logs_check' not in args_dict.keys():
            args_dict['logs_check'] = 1
        if 'fnl_flag' not in args_dict.keys():
            args_dict['fnl_flag'] = 0
        if 'exclude_log_check_pattern' not in args_dict.keys():
            args_dict['exclude_log_check_pattern'] = ''

        fail_flag = []
        validation_msgs = ''

        # Method global variables
        validation_msgs += '\nFor DUT '+str(dut.alias)+'\n****************************\n'

        # Verification for consistency checker
        if args_dict['cc_check']:
            validation_msgs += "\n\nConsistency Check Data : "+\
                                " :\n==========================\n"
            cc_args_dict = {
                'dut'                   : dut,
                'fnl_flag'              : args_dict['fnl_flag']
            }
            ccData = self.verifyBasicVxLANCC(cc_args_dict)
            fail_flag.append(ccData['status'])
            validation_msgs += ccData['logs']
        else:
            validation_msgs += 'Consistency Check Skipped as per user Request\n'

        # Verification for failed logs
        if args_dict['logs_check']:
            error_pattern = 'CRASHED|failed|CPU Hog|malloc|core dump|mts_send|redzone|error'
            skip_pattern = str(args_dict['exclude_log_check_pattern'])
            device_error_logs_dump = dut.execute("show logg logf | egr ig '"+str(error_pattern)+"' | ex ig '"+str(skip_pattern)+"'")
            if device_error_logs_dump != '':
                device_error_log_lst = device_error_logs_dump.split('\n')
                dut.configure("clear logging logfile")
                if len(device_error_log_lst) > 0:
                    validation_msgs += "\n\n\nError logs found - count : "+\
                                        str(len(device_error_log_lst))+\
                                        " :\n================================\n\n"+\
                                        str(device_error_logs_dump)+"\n\n"
                    fail_flag.append(0)
            else:
                validation_msgs += '\nNo Error Logs seen\n'
        else:
            validation_msgs += 'Error Logs Check Skipped as per user Request\n'

        # Verification for cores
        if args_dict['cores_check']:
            cores_output_dump = dut.execute("sh cores vdc-all | json        ")
            if cores_output_dump != '':
                cores_output = json.loads(cores_output_dump)
                cores_dump = cores_output['TABLE_cores']['ROW_cores']
                if len(cores_dump) > 0 and type(cores_dump) is list:
                    fail_flag.append(0)
                    validation_msgs += "\nCores found - count : "+\
                                        str(len(cores_dump))+\
                                        " :\n==========================\n\n"
                    for core_line in cores_dump:
                        dut.execute('copy core://'+str(core_line['module_id'])+'/'+str(core_line['pid'])+'/'+str(core_line['instance'])+' bootflash:')
                        core_flash_out = (str(dut.execute('dir bootflash: | i i "'+str(core_line['pid'])+'|'+str(core_line['process_name'])+'"'))).split(' ')
                        validation_msgs += "Process - "+str(core_line['process_name'])+"\t - bootflash:"+str(core_flash_out[-1])+'\n'
                elif type(cores_dump) is dict:
                    dut.execute('copy core://'+str(cores_dump['module_id'])+'/'+str(cores_dump['pid'])+'/'+str(cores_dump['instance'])+' bootflash:')
                    core_flash_out = (str(dut.execute('dir bootflash: | i i "'+str(cores_dump['pid'])+'|'+str(cores_dump['process_name'])+'"'))).split(' ')
                    validation_msgs += "Process - "+str(cores_dump['process_name'])+"\t - bootflash:"+str(core_flash_out[-1])+'\n'

                dut.configure("clear cores")
            else:
                validation_msgs += '\nNo Cores seen\n'
        else:
            validation_msgs += 'Cores Check Skipped as per user Request\n'

        if 0 in fail_flag:
            return {'status': 0, 'logs':validation_msgs}
        else:
            return {'status': 1, 'logs': validation_msgs}

    # ====================================================================================================#
    def postTestVerification(self, args_dict):

        help_string = """
        ==================================================================================================================================

           Proc Name           : postTestVerification

           Functionality       : Verify Error Logs, Cores and CC as Post Trigger checks

           Parameters          : A dictionary with below key_value pairs.

           Name                         Required       Description                  Default Value       Value Options
           ====                         ==========      ===========                 =============       =============
           duts                         :   M   :   List of DUTs                        : N/A            : N/A
           cc_check                     :   O   :   Check Consistency-checker           : 1              : 0 or 1
           cores_check                  :   O   :   Check core-files                    : 1              : 0 or 1
           logs_check                   :   O   :   Check for error-logs                : 1              : 0 or 1
           exclude_log_check_pattern    :   O   :   exclude pattern in log check        : ''             : N/A
           fnl_flag                     :   O   :   FnL Flag to skip VxLAN VLAN ALL CC  : 0              : 0 or 1

           Parameter Example   :

                               ArgDict = {
                                    'dut'                       ; [LEAF_1, LEAF_2, LEAF_3]
                                    'cc_check'                  : 1,
                                    'cores_check'               : 1,
                                    'logs_check'                : 1,
                                    'fnl_flag'                  : 1,
                                    'exclude_log_check_pattern' : 'ERROR_VLANS_SUSPENDED|ERROR_VLANS_REMOVED',
                                }

            Return Value        : Fail Case:
                                  {'status': 0, 'logs': validation_msgs} 
                                  Pass Case:
                                  {'status': 1, 'logs': validation_msgs}   

        ==================================================================================================================================
        """

        # Define Arguments Definition
        args_def = [
            ('dut_list',                    'M', [list]),
            ('cc_check',                    'o', [str, int]),
            ('cores_check',                 'o', [str, int]),
            ('logs_check',                  'o', [str, int]),
            ('exclude_log_check_pattern',   'o', [str, int]),
            ('fnl_flag',                    'o', [str, int]),
        ]

        # Validate Arguments
        try:
            ArgVal.validate(args_def, **args_dict)
        except Exception as e:
            print("Exception seen:" + str(e))
            log.info("Exception seen:" + str(e))
            log.info(help_string)
            return 0

        # Setting up the default values
        if 'cc_check' not in args_dict.keys():
            args_dict['cc_check'] = 1
        if 'cores_check' not in args_dict.keys():
            args_dict['cores_check'] = 1
        if 'logs_check' not in args_dict.keys():
            args_dict['logs_check'] = 1
        if 'fnl_flag' not in args_dict.keys():
            args_dict['fnl_flag'] = 0
        if 'exclude_log_check_pattern' not in args_dict.keys():
            args_dict['exclude_log_check_pattern'] = ''

        fail_flag = []
        arg_list = []
        validation_msgs = ''

        dut_list = args_dict['dut_list']
        # args_dict.pop('dut_list')
        for _ in dut_list:
            arg_list.append(args_dict)

        postTestCheck_ParallelCall = pcall(self.system_ERR_CORES_CC_Check, dut=dut_list, args_dict=arg_list)
        for result in postTestCheck_ParallelCall:
            fail_flag.append(result['status'])
            validation_msgs += str(result['logs'])
        args_dict['dut_list'] = dut_list

        if 0 in fail_flag:
            return {'status': 0, 'logs': validation_msgs}
        else:
            return {'status': 1, 'logs': validation_msgs}
