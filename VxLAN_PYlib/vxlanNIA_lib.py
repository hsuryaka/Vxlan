"""
 VxLAN NIA Library for EVPN and Flood and Learn
"""

import logging
import json
import texttable
import collections
import re
import ipaddress as ip

import unicon.statemachine.statemachine

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

# ====================================================================================================#
# set global debug flag
# ====================================================================================================#
global_debug_flag = 1


# ====================================================================================================#
# Nexus 39K VxLAN EVPN Configuration Methods
# ====================================================================================================#
class verifyVxlanNIA:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self):
        pass

    # ====================================================================================================#
    @staticmethod
    def buildNIACLI(inpDict):

        # --------------------------------------------
        # Setting few default parameters
        # --------------------------------------------
        if 'vlan' not in inpDict['cli_params'].keys():
            inpDict['cli_params']['vlan'] = 0
        if 'cc_flag' not in inpDict['cli_params'].keys():
            inpDict['cli_params']['cc_flag'] = 0
        if 'traffic' not in inpDict['cli_params'].keys():
            inpDict['cli_params']['traffic'] = 0

        # --------------------------------------------
        # Build NIA CLI and execute
        # --------------------------------------------
        niaCLI = "show nia validate flow"

        # Add SRC parameters
        niaCLI += " src " + str(inpDict['cli_params']['src'])
        if 'smac' in inpDict['cli_params'].keys():
            niaCLI += " smac " + str(inpDict['cli_params']['smac'])

        # Add DST parameters
        niaCLI += " dest " + str(inpDict['cli_params']['dest'])
        if 'dmac' in inpDict['cli_params'].keys():
            niaCLI += " dmac " + str(inpDict['cli_params']['dmac'])

        # Add IIF parameters
        niaCLI += " iif " + str(inpDict['cli_params']['iif'])

        # Add VLAN parameters
        niaCLI += " vlan " + str(inpDict['cli_params']['vlan'])

        # Add ELAM Flag parameters
        if 'traffic' in inpDict['cli_params'].keys():
            niaCLI += " traffic " + str(inpDict['cli_params']['traffic'])

        # Add CC Flag parameters
        niaCLI += " cc " + str(inpDict['cli_params']['cc_flag'])

        # Add upper iif
        if 'upper_iif' in inpDict['cli_params'].keys():
            niaCLI += " upper_iif " + str(inpDict['cli_params']['upper_iif'])

        # Add pipe and no-more
        niaCLI += " | no"

        return niaCLI

    # ====================================================================================================#
    @staticmethod
    def validateNIAStatusInputParameters(niaCLIData, inpDict):

        # --------------------------------------------
        # Setting few default parameters
        # --------------------------------------------
        if 'vlan' not in inpDict['cli_params'].keys():
            inpDict['cli_params']['vlan'] = 0
        if 'cc_flag' not in inpDict['cli_params'].keys():
            inpDict['cli_params']['cc_flag'] = 0
        if 'traffic' not in inpDict['cli_params'].keys():
            inpDict['cli_params']['traffic'] = 0

        # --------------------------------------------
        # Proc level global variables
        # --------------------------------------------
        niaVerificationStatus   = []
        niaVerificationMsgs     = ""

        # --------------------------------------------
        # Create and Initialize tables
        # --------------------------------------------
        niaStatusTable = texttable.Texttable()
        niaStatusTable.header(['Task', 'Status', 'Reason'])
        niaStatusTable.set_cols_width([20,10,70])

        niaInputValidationTable = texttable.Texttable()
        niaInputValidationTable.header(['Parameter', 'Status', 'Passed / Expected Value', 'Observed Value'])
        niaInputValidationTable.set_cols_width([30,10,35,35])

        # --------------------------------------------
        # Record the NIA execution status
        # --------------------------------------------
        if niaCLIData['result']:
            niaStatusTable.add_row(['NIA CLI Execution','FAIL', niaCLIData['result_reason']])
            niaVerificationStatus.append(0)
        else:
            niaStatusTable.add_row(['NIA CLI Execution', 'PASS','-'])

        if niaCLIData['temp_cc_result']:
            niaStatusTable.add_row(['NIA CC Execution', 'FAIL', niaCLIData['temp_result_reason'][0]])
            niaVerificationStatus.append(0)
        else:
            niaStatusTable.add_row(['NIA CC Execution', 'PASS', '-'])

        niaVerificationMsgs += "\n\nNIA State Validator Status \n"
        niaVerificationMsgs += "==================================================================\n"
        niaVerificationMsgs += niaStatusTable.draw()

        # --------------------------------------------
        # Validate Input section
        # --------------------------------------------
        # Checking the Source src parameter
        if niaCLIData['input']['src'] == inpDict['cli_params']['src']:
            niaInputValidationTable.add_row(['SRC','PASS', inpDict['cli_params']['src'], niaCLIData['input']['src']])
        else:
            niaInputValidationTable.add_row(['SRC', 'FAIL', inpDict['cli_params']['src'], niaCLIData['input']['src']])
            niaVerificationStatus.append(0)

        # --------------------------------------------
        # Checking the Source Mac smac parameter
        if 'smac' in inpDict['cli_params'].keys():
            observerSMac_simple  = str(niaCLIData['input']['smac']).translate({ord(i): None for i in ':.-'})
            passedSMac_simple    = str(inpDict['cli_params']['smac']).translate({ord(i): None for i in ':.-'})
            if observerSMac_simple == passedSMac_simple:
                niaInputValidationTable.add_row(['SMAC','PASS', inpDict['cli_params']['smac'], niaCLIData['input']['smac']])
            else:
                niaInputValidationTable.add_row(['SMAC', 'FAIL', inpDict['cli_params']['smac'], niaCLIData['input']['smac']])
                niaVerificationStatus.append(0)

        # --------------------------------------------
        # Checking the Destination dest parameter
        if niaCLIData['input']['dest'] == inpDict['cli_params']['dest']:
            niaInputValidationTable.add_row(['DEST', 'PASS', inpDict['cli_params']['dest'], niaCLIData['input']['dest']])
        else:
            niaInputValidationTable.add_row(['DEST', 'FAIL', inpDict['cli_params']['dest'], niaCLIData['input']['dest']])
            niaVerificationStatus.append(0)

        # --------------------------------------------
        # Checking the Destination Mac dmac parameter
        if 'dmac' in inpDict['cli_params'].keys():
            observerDMac_simple  = str(niaCLIData['input']['dmac']).translate({ord(i): None for i in ':.-'})
            passedDMac_simple    = str(inpDict['cli_params']['dmac']).translate({ord(i): None for i in ':.-'})
            if observerDMac_simple == passedDMac_simple:
                niaInputValidationTable.add_row(['DMAC', 'PASS', inpDict['cli_params']['dmac'], niaCLIData['input']['dmac']])
            else:
                niaInputValidationTable.add_row(['DMAC', 'FAIL', inpDict['cli_params']['dmac'], niaCLIData['input']['dmac']])
                niaVerificationStatus.append(0)

        # --------------------------------------------
        # Checking the Incoming Interface iif parameter
        if niaCLIData['input']['iif'][0] == inpDict['cli_params']['iif']:
            niaInputValidationTable.add_row(['IIF', 'PASS', inpDict['cli_params']['iif'], niaCLIData['input']['iif'][0]])
        else:
            niaInputValidationTable.add_row(['IIF', 'FAIL', inpDict['cli_params']['iif'], niaCLIData['input']['iif'][0]])
            niaVerificationStatus.append(0)

        # --------------------------------------------
        # Checking the VLAN Flag cc parameter
        if str(niaCLIData['input']['vlan']) == str(inpDict['cli_params']['vlan']):
            niaInputValidationTable.add_row(['VLAN','PASS', inpDict['cli_params']['vlan'], niaCLIData['input']['vlan']])
        else:
            niaInputValidationTable.add_row(['VLAN', 'FAIL', inpDict['cli_params']['vlan'], niaCLIData['input']['vlan']])
            niaVerificationStatus.append(0)

        # --------------------------------------------
        # Checking the CC Flag cc parameter
        if str(niaCLIData['input']['cc']) == str(inpDict['cli_params']['cc_flag']):
            niaInputValidationTable.add_row(['CC','PASS', inpDict['cli_params']['cc_flag'], niaCLIData['input']['cc']])
        else:
            niaInputValidationTable.add_row(['CC', 'FAIL', inpDict['cli_params']['cc_flag'], niaCLIData['input']['cc']])
            niaVerificationStatus.append(0)

        # --------------------------------------------
        # Checking the CC Flag cc parameter
        if 'traffic' in inpDict['cli_params'].keys():
            if str(niaCLIData['input']['traffic']) == str(inpDict['cli_params']['traffic']):
                niaInputValidationTable.add_row(['traffic','PASS', inpDict['cli_params']['traffic'], niaCLIData['input']['traffic']])
            else:
                niaInputValidationTable.add_row(['traffic', 'FAIL', inpDict['cli_params']['traffic'], niaCLIData['input']['traffic']])
                niaVerificationStatus.append(0)

        # --------------------------------------------
        # Checking the CC Flag cc parameter
        if 'upper_iif' in inpDict['cli_params'].keys():
            niaInputValidationTable.add_row(['upper_iif', 'PASS', inpDict['cli_params']['upper_iif'], "NA"])

        niaVerificationMsgs += "\n\nNIA Input Validation Status \n"
        niaVerificationMsgs += "==================================================================\n"
        niaVerificationMsgs += niaInputValidationTable.draw()

        if 0 in niaVerificationStatus:
            return {'result': 0, 'log': niaVerificationMsgs}
        else:
            return {'result': 1, 'log': niaVerificationMsgs}

    # ====================================================================================================#
    @staticmethod
    def validateNIACCData(niaCLIData):

        # --------------------------------------------
        # Proc level global variables
        # --------------------------------------------
        niaVerificationStatus   = []
        niaVerificationMsgs     = ""

        # --------------------------------------------
        # Create and Initialize tables
        # --------------------------------------------
        niaPassedCCTable = texttable.Texttable()
        niaPassedCCTable.header(['CC Type', 'Status', 'CC Cmd Used'])
        niaPassedCCTable.set_cols_width([30,10,100])

        niaFailedCCTable = texttable.Texttable()
        niaFailedCCTable.header(['CC Type', 'Status', 'CC Cmd Used'])
        niaFailedCCTable.set_cols_width([30,10,100])

        niaSkippedCCTable = texttable.Texttable()
        niaSkippedCCTable.header(['Status', 'CC Cmd Used', 'output'])
        niaSkippedCCTable.set_cols_width([30,70,70])

        niaUnsupportedCCTable = texttable.Texttable()
        niaUnsupportedCCTable.header(['Status', 'CC Cmd Used', 'Output'])
        niaUnsupportedCCTable.set_cols_width([30,70,70])

        niaUnmodelledCCTable = texttable.Texttable()
        niaUnmodelledCCTable.header(['Status', 'CC Cmd Used'])
        niaUnmodelledCCTable.set_cols_width([30,70])

        # --------------------------------------------
        # Validate CC and populate the Tables
        # --------------------------------------------
        if len(niaCLIData['output']['passed_CC']) != 0:
            niaVerificationMsgs += "\n\nNIA Passed Consistency Checker Validation Status \n"
            niaVerificationMsgs += "==================================================================\n"
            for passedCCItem in niaCLIData['output']['passed_consistency_checker']:
                niaPassedCCTable.add_row([passedCCItem['type'], 'PASS', passedCCItem['cmd']])
            niaVerificationMsgs += niaPassedCCTable.draw() + "\n"

        if len(niaCLIData['output']['failed_CC']) != 0:
            niaVerificationMsgs += "\n\nNIA Failed Consistency Checker Validation Status \n"
            niaVerificationMsgs += "==================================================================\n"
            niaVerificationStatus.append(0)
            for failedCCItem in niaCLIData['output']['failed_consistency_checker']:
                niaFailedCCTable.add_row([failedCCItem['type'], 'FAIL', failedCCItem['cmd']])
            niaVerificationMsgs += niaFailedCCTable.draw()

        if len(niaCLIData['output']['skipped_CC']) != 0:
            niaVerificationMsgs += "\n\nNIA Skipped Consistency Checker Validation Status \n"
            niaVerificationMsgs += "==================================================================\n"
            niaVerificationStatus.append(0)
            for skippedCCItem in niaCLIData['output']['failed_consistency_checker']:
                niaSkippedCCTable.add_row(['SKIPPED', skippedCCItem['cmd'], skippedCCItem['output']])
            niaVerificationMsgs += niaSkippedCCTable.draw()

        if len(niaCLIData['output']['unsupported_CC']) != 0:
            niaVerificationMsgs += "\n\nNIA Un-supported Consistency Checker Validation Status \n"
            niaVerificationMsgs += "==================================================================\n"
            niaVerificationStatus.append(0)
            for unsupportedCCItem in niaCLIData['output']['unsupported_CC_details']:
                niaUnsupportedCCTable.add_row(['UN-SUPPORTED', unsupportedCCItem['cmd'], unsupportedCCItem['output']])
            niaVerificationMsgs += niaUnsupportedCCTable.draw()

        if len(niaCLIData['output']['unmodelled_CC']) != 0:
            niaVerificationMsgs += "\n\nNIA Un-modelled Consistency Checker Validation Status \n"
            niaVerificationMsgs += "==================================================================\n"
            niaVerificationStatus.append(0)
            for unmodelledCCItem in niaCLIData['output']['unmodelled_CC_details']:
                niaUnmodelledCCTable.add_row(['UN-MODELLED', unmodelledCCItem])
            niaVerificationMsgs += niaUnmodelledCCTable.draw()

        if 0 in niaVerificationStatus:
            return {'result': 0, 'log': niaVerificationMsgs}
        else:
            return {'result': 1, 'log': niaVerificationMsgs}

    # ====================================================================================================#
    @staticmethod
    def validateNIAElementData(niaCLIData, elemDict):

        # --------------------------------------------
        # Proc level global variables
        # --------------------------------------------
        niaVerificationStatus   = []
        niaVerificationMsgs     = ""
        niaElemData = niaCLIData['output']['element']
        compare = lambda x, y: collections.Counter(x) == collections.Counter(y)

        # --------------------------------------------
        # Create and Initialize tables
        # --------------------------------------------
        niaElementTable = texttable.Texttable()
        niaElementTable.header(['Element', 'Status', 'Passed / Expected Value', 'Observed Value'])
        niaElementTable.set_cols_width([30,10,35,35])

        niaVerificationMsgs += "\n\nNIA Element Validation Status \n"
        niaVerificationMsgs += "==================================================================\n"

        # --------------------------------------------
        # Validate Element BD
        # --------------------------------------------
        # Check BD key is present in Passed Dict
        if 'BD' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['BD'] and not niaElemData['BD']) \
                    or (not elemDict['BD'] and niaElemData['BD']) \
                    or (len(elemDict['BD']) != len(niaElemData['BD'])):
                niaElementTable.add_row(['BD', 'FAIL', elemDict['BD'], niaElemData['BD']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("BD-if-1"+str((['BD', 'FAIL', elemDict['BD'], niaElemData['BD']])))
            # Compare the passed and observed data
            elif compare(elemDict['BD'],niaElemData['BD']):
                niaElementTable.add_row(['BD', 'PASS', elemDict['BD'], niaElemData['BD']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['BD', 'FAIL', elemDict['BD'], niaElemData['BD']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("BD-else")
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['BD', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element iif
        # --------------------------------------------
        # Check iif key is present in Passed Dict
        if 'iif' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['iif'] and not niaElemData['iif']) \
                    or (not elemDict['iif'] and niaElemData['iif']) \
                    or (len(elemDict['iif']) != len(niaElemData['iif'])):
                niaElementTable.add_row(['iif', 'FAIL', elemDict['iif'], niaElemData['iif']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(elemDict['iif'],niaElemData['iif']):
                niaElementTable.add_row(['iif', 'PASS', elemDict['iif'], niaElemData['iif']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['iif', 'FAIL', elemDict['iif'], niaElemData['iif']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['iif', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element in_lif
        # --------------------------------------------
        # Check in_lif key is present in Passed Dict
        if 'in_lif' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['in_lif'] and not niaElemData['in_lif']) \
                    or (not elemDict['in_lif'] and niaElemData['in_lif']) \
                    or (len(elemDict['in_lif']) != len(niaElemData['in_lif'])):
                niaElementTable.add_row(['in_lif', 'FAIL', elemDict['in_lif'], niaElemData['in_lif']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(elemDict['in_lif'],niaElemData['in_lif']):
                niaElementTable.add_row(['in_lif', 'PASS', elemDict['in_lif'], niaElemData['in_lif']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['in_lif', 'FAIL', elemDict['in_lif'], niaElemData['in_lif']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['in_lif', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element macAddr
        # --------------------------------------------

        # Check macAddr key is present in Passed Dict
        if 'in_po_mbrs' in elemDict.keys():

            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['in_po_mbrs'] and not niaElemData['in_po_mbrs']) \
                    or (not elemDict['in_po_mbrs'] and niaElemData['in_po_mbrs']) \
                    or (len(elemDict['in_po_mbrs']) != len(niaElemData['in_po_mbrs'])):
                niaElementTable.add_row(['in_po_mbrs', 'FAIL', elemDict['in_po_mbrs'], niaElemData['in_po_mbrs']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(elemDict['in_po_mbrs'],niaElemData['in_po_mbrs']):
                niaElementTable.add_row(['in_po_mbrs', 'PASS', elemDict['in_po_mbrs'], niaElemData['in_po_mbrs']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['in_po_mbrs', 'FAIL', elemDict['in_po_mbrs'], niaElemData['in_po_mbrs']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['in_po_mbrs', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element in_vlan
        # --------------------------------------------
        # Check in_vlan key is present in Passed Dict
        if 'in_vlan' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['in_vlan'] and not niaElemData['in_vlan']) \
                    or (not elemDict['in_vlan'] and niaElemData['in_vlan']) \
                    or (len(elemDict['in_vlan']) != len(niaElemData['in_vlan'])):
                niaElementTable.add_row(['in_vlan', 'FAIL', elemDict['in_vlan'], niaElemData['in_vlan']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(elemDict['in_vlan'],niaElemData['in_vlan']):
                niaElementTable.add_row(['in_vlan', 'PASS', elemDict['in_vlan'], niaElemData['in_vlan']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['in_vlan', 'FAIL', elemDict['in_vlan'], niaElemData['in_vlan']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['in_vlan', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element in_vrf
        # --------------------------------------------
        # Check in_vrf key is present in Passed Dict
        if 'in_vrf' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['in_vrf'] and not niaElemData['in_vrf']) \
                    or (not elemDict['in_vrf'] and niaElemData['in_vrf']) \
                    or (len(elemDict['in_vrf']) != len(niaElemData['in_vrf'])):
                niaElementTable.add_row(['in_vrf', 'FAIL', elemDict['in_vrf'], niaElemData['in_vrf']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(elemDict['in_vrf'],niaElemData['in_vrf']):
                niaElementTable.add_row(['in_vrf', 'PASS', elemDict['in_vrf'], niaElemData['in_vrf']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['in_vrf', 'FAIL', elemDict['in_vrf'], niaElemData['in_vrf']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['in_vrf', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element macAddr
        # --------------------------------------------
        passedMacWithoutLimiter = []
        observedMacWithoutLimiter = []

        # Check macAddr key is present in Passed Dict
        if 'macAddr' in elemDict.keys():

            # Modify mac addresses to remove limiters
            for passedMac in elemDict['macAddr']:
                passedMacWithoutLimiter.append(str(passedMac).translate({ord(i): None for i in ':.-'}))
            for observedMac in niaElemData['macAddr']:
                observedMacWithoutLimiter.append(str(observedMac).translate({ord(i): None for i in ':.-'}))

            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['macAddr'] and not niaElemData['macAddr']) \
                    or (not elemDict['macAddr'] and niaElemData['macAddr']) \
                    or (len(elemDict['macAddr']) != len(niaElemData['macAddr'])):
                niaElementTable.add_row(['MacAddr', 'FAIL', elemDict['macAddr'], niaElemData['macAddr']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("macAddr-if-1")
            # Compare the passed and observed data
            elif compare(passedMacWithoutLimiter,observedMacWithoutLimiter):
                niaElementTable.add_row(['MacAddr', 'PASS', elemDict['macAddr'], niaElemData['macAddr']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['MacAddr', 'FAIL', elemDict['macAddr'], niaElemData['macAddr']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("macAddr-else")
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['MacAddr', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element module
        # --------------------------------------------
        # Check BD key is present in Passed Dict
        if 'module' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['module'] and not niaElemData['module']) \
                    or (not elemDict['module'] and niaElemData['module']) \
                    or (len(elemDict['module']) != len(niaElemData['module'])):
                niaElementTable.add_row(['MODULE', 'FAIL', elemDict['module'], niaElemData['module']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("module-if-1")
            # Compare the passed and observed data
            elif compare(elemDict['module'],niaElemData['module']):
                niaElementTable.add_row(['MODULE', 'PASS', elemDict['module'], niaElemData['module']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['MODULE', 'FAIL', elemDict['module'], niaElemData['module']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("module-else")
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['MODULE', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element port
        # --------------------------------------------
        # Check port key is present in Passed Dict
        if 'port' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same

            elemDict['port'].sort()
            niaElemData['port'].sort()

            # Zipping both the passed and observed list of dicts
            passed_data,observed_data = [],[]
            iterator = 0
            # Modifying the Ethernet to Eth
            for passed_item,observed_item in zip(elemDict['port'], niaElemData['port']):
                Passed_int_item    = re.search('ethernet(\\d.*)', passed_item,re.I)
                Observed_int_item  = re.search('eth(\\d.*)', observed_item,re.I)
                if Passed_int_item and Observed_int_item:
                    passed_item = "Eth" + str(Passed_int_item.group(1))
                elemDict['port'][iterator] = passed_item
                iterator+=1

            if (elemDict['port'] and not niaElemData['port']) \
                    or (not elemDict['port'] and niaElemData['port']) \
                    or (len(elemDict['port']) != len(niaElemData['port'])):
                niaElementTable.add_row(['PORT', 'FAIL', elemDict['port'], niaElemData['port']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(passed_data,observed_data):
                niaElementTable.add_row(['PORT', 'PASS', elemDict['port'], niaElemData['port']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['PORT', 'FAIL', elemDict['port'], niaElemData['port']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['PORT', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element vlan
        # --------------------------------------------
        # Check vlan key is present in Passed Dict
        if 'vlan' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['vlan'] and not niaElemData['vlan']) \
                    or (not elemDict['vlan'] and niaElemData['vlan']) \
                    or (len(elemDict['vlan']) != len(niaElemData['vlan'])):
                niaElementTable.add_row(['VLAN', 'FAIL', elemDict['vlan'], niaElemData['vlan']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("vlan-if-1")
            # Compare the passed and observed data
            elif compare(elemDict['vlan'],niaElemData['vlan']):
                niaElementTable.add_row(['VLAN', 'PASS', elemDict['vlan'], niaElemData['vlan']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['VLAN', 'FAIL', elemDict['vlan'], niaElemData['vlan']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("vlan-else")
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['VLAN', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element vni
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'vni' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['vni'] and not niaElemData['vni']) \
                    or (not elemDict['vni'] and niaElemData['vni']) \
                    or (len(elemDict['vni']) != len(niaElemData['vni'])):
                niaElementTable.add_row(['VNI', 'FAIL', elemDict['vni'], niaElemData['vni']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("vni-if-1")
            # Compare the passed and observed data
            elif compare(elemDict['vni'],niaElemData['vni']):
                niaElementTable.add_row(['VNI', 'PASS', elemDict['vni'], niaElemData['vni']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['VNI', 'FAIL', elemDict['vni'], niaElemData['vni']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("vni-else")
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['VNI', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Placeholder for VPC attribute
        # --------------------------------------------
        # Check vpc key is present in Passed Dict
        if 'vpc' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if len(elemDict['vpc']) == len(niaElemData['vpc']):
                if elemDict['vpc'] == [] and niaElemData['vpc'] == []:
                    niaElementTable.add_row(['VPC', 'PASS', elemDict['vpc'], niaElemData['vpc']])
                elif (elemDict['vpc'] and not niaElemData['vpc']) or (not elemDict['vpc'] and niaElemData['vpc']):
                    niaElementTable.add_row(['VPC', 'FAIL', elemDict['vpc'], niaElemData['vpc']])
                    niaVerificationStatus.append(0)
                # Compare the passed and observed data
                elif set(elemDict['vpc']) == set(niaElemData['vpc']):
                    niaElementTable.add_row(['VPC', 'PASS', elemDict['vpc'], niaElemData['vpc']])
                # If every check fails then return fail
                else:
                    niaElementTable.add_row(['VPC', 'FAIL', elemDict['vpc'], niaElemData['vpc']])
                    niaVerificationStatus.append(0)
            # If argument is not passed ignore
        else:
            niaElementTable.add_row(['VPC', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element iif_vrf
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'iif_vrf' in elemDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elemDict['iif_vrf'] and not niaCLIData['output']['iif_vrf']) \
                    or (not elemDict['iif_vrf'] and niaCLIData['output']['iif_vrf']):
                niaElementTable.add_row(['IIF_VRF', 'FAIL', elemDict['iif_vrf'], niaCLIData['output']['iif_vrf']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("iif_vrf-if-1")
            # Compare the passed and observed data
            elif elemDict['iif_vrf'] == niaCLIData['output']['iif_vrf']:
                niaElementTable.add_row(['IIF_VRF', 'PASS', elemDict['iif_vrf'], niaCLIData['output']['iif_vrf']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['IIF_VRF', 'FAIL', elemDict['iif_vrf'], niaCLIData['output']['iif_vrf']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("iif_vrf-else")
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['IIF_VRF', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element route
        # --------------------------------------------
        # Check last_path key is present in Passed Dict
        if 'route' in elemDict.keys():

            # Compare the passed and observed data
            each_item_check = [1]
            if (niaElemData['route'] == [] and elemDict['route'] != []) or (niaElemData['route'] != [] and elemDict['route'] == []):
                each_item_check.append(0)
            elif niaElemData['route'] == [] and elemDict['route'] == []:
                niaElementTable.add_row(['ROUTE', 'PASS', elemDict['route'], niaElemData['route']])
                each_item_check.append(1)
            elif niaElemData['route'] != [] and elemDict['route'] != []:
                if len(niaElemData['route']) != len(elemDict['route']):
                    each_item_check.append(0)
                else:
                    for passed,observed in zip(niaElemData['route'],elemDict['route']):
                        for key in (set(passed.keys()).intersection(set(observed.keys()))):
                            if passed[key] != observed[key]:
                                each_item_check.append(0)

            # Check for any failures and report
            if 0 in each_item_check and (each_item_check != []):
                niaElementTable.add_row(['ROUTE', 'FAIL', elemDict['route'], niaElemData['route']])
                niaVerificationStatus.append(0)
            elif each_item_check:
                niaElementTable.add_row(['ROUTE', 'PASS', elemDict['route'], niaElemData['route']])
            else:
                niaElementTable.add_row(['ROUTE', 'FAIL', elemDict['route'], niaElemData['route']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['ROUTE', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element last_path
        # --------------------------------------------
        # Check last_path key is present in Passed Dict
        if 'last_path' in elemDict.keys():

            # Zipping both the passed and observed list of dicts
            lastPathPassedObservedZip = zip(elemDict['last_path'], niaCLIData['output']['last_path'])

            # Compare the passed and observed data
            if (any(passed == observed for passed, observed in lastPathPassedObservedZip)) \
                    or ((niaCLIData['output']['last_path'] == []) and (elemDict['last_path'] == [])):
                niaElementTable.add_row(['LAST_PATH', 'PASS', elemDict['last_path'], niaCLIData['output']['last_path']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['LAST_PATH', 'FAIL', elemDict['last_path'], niaCLIData['output']['last_path']])
                niaVerificationStatus.append(0)
                if global_debug_flag:
                    print("last-path-else")
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['LAST_PATH', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element paths
        # --------------------------------------------
        # Check paths key is present in Passed Dict
        if 'paths' in elemDict.keys():

            # Zipping both the passed and observed list of dicts
            passed,observed = {},{}
            each_item_check = [1]
            if len(elemDict['paths']) == len(niaCLIData['output']['paths']):
                lastPathPassedObservedZip = zip(elemDict['paths'], niaCLIData['output']['paths'])
                # Modifying the Ethernet to Eth
                for passed,observed in lastPathPassedObservedZip:
                    logOIFMod_Passed    = re.search('ethernet(\\d.*)', passed['log_oif'],re.I)
                    phyOIFMod_Passed    = re.search('ethernet(\\d.*)', passed['phy_oif'], re.I)
                    logOIFMod_Observed  = re.search('eth(\\d.*)', observed['log_oif'],re.I)
                    phyOIFMod_Observed  = re.search('eth(\\d.*)', observed['phy_oif'], re.I)
                    if logOIFMod_Passed and logOIFMod_Observed:
                        passed['log_oif'] = "Eth" + str(logOIFMod_Passed.group(1))
                    if phyOIFMod_Passed and phyOIFMod_Observed:
                        passed['phy_oif'] = "Eth" + str(phyOIFMod_Passed.group(1))

                # Compare the passed and observed data
                if passed != {} and observed != {}:
                    if set(passed.keys()) == set(observed.keys()):
                        for key in (set(passed.keys()).intersection(set(observed.keys()))):
                            if passed[key] != observed[key]:
                                each_item_check.append(0)
                    else:
                        each_item_check.append(0)
            else:
                each_item_check.append(0)

            # Check for any failures and report
            if 0 in each_item_check and (each_item_check != []):
                niaElementTable.add_row(['PATHS', 'FAIL', elemDict['paths'], niaCLIData['output']['paths']])
                niaVerificationStatus.append(0)
            elif each_item_check:
                niaElementTable.add_row(['PATHS', 'PASS', elemDict['paths'], niaCLIData['output']['paths']])

        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['PATHS', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        niaVerificationMsgs += niaElementTable.draw()

        if 0 in niaVerificationStatus:
            return {'result': 0, 'log': niaVerificationMsgs}
        else:
            return {'result': 1, 'log': niaVerificationMsgs}

    # ====================================================================================================#
    @staticmethod
    def validateNIAELAMData(niaCLIData, elamDict):

        # --------------------------------------------
        # Proc level global variables
        # --------------------------------------------
        niaVerificationStatus   = []
        niaVerificationMsgs     = ""
        niaElamData = niaCLIData['output']['disclosure_elam']
        compare = lambda x, y: collections.Counter(x) == collections.Counter(y)

        # --------------------------------------------
        # Create and Initialize tables
        # --------------------------------------------
        niaElementTable = texttable.Texttable()
        niaElementTable.header(['Element', 'Status', 'Passed / Expected Value', 'Observed Value'])
        niaElementTable.set_cols_width([30,10,35,35])

        niaVerificationMsgs += "\n\nNIA ELAM Validation Status \n"
        niaVerificationMsgs += "==================================================================\n"

        # --------------------------------------------
        # Validate Element Packet Type
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'Packet Type' in elamDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Packet Type'] and not niaElamData['Packet Type']) \
                    or (not elamDict['Packet Type'] and niaElamData['Packet Type']):
                niaElementTable.add_row(['Packet Type', 'FAIL', elamDict['Packet Type'], niaElamData['Packet Type']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif elamDict['Packet Type'] == niaElamData['Packet Type']:
                niaElementTable.add_row(['Packet Type', 'PASS', elamDict['Packet Type'], niaElamData['Packet Type']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Packet Type', 'FAIL', elamDict['Packet Type'], niaElamData['Packet Type']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Packet Type', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element Source IP
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'Source IP' in elamDict.keys():
            if elamDict['Packet Type'] == "IPv6":
                temp_ip_store = str(ip.IPv6Interface(elamDict['Source IP']).exploded)
                temp_ip_store = temp_ip_store.rstrip('/128')
                elamDict['Source IP'] = temp_ip_store

            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Source IP'] and not niaElamData['Source IP']) \
                    or (not elamDict['Source IP'] and niaElamData['Source IP']):
                niaElementTable.add_row(['Source IP', 'FAIL', elamDict['Source IP'], niaElamData['Source IP']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif elamDict['Source IP'] == niaElamData['Source IP']:
                niaElementTable.add_row(['Source IP', 'PASS', elamDict['Source IP'], niaElamData['Source IP']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Source IP', 'FAIL', elamDict['Source IP'], niaElamData['Source IP']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Source IP', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element Destination IP
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'Destination IP' in elamDict.keys():
            if elamDict['Packet Type'] == "IPv6":
                temp_ip_store = str(ip.IPv6Interface(elamDict['Destination IP']).exploded)
                temp_ip_store = temp_ip_store.rstrip('/128')
                elamDict['Destination IP'] = temp_ip_store

            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Destination IP'] and not niaElamData['Destination IP']) \
                    or (not elamDict['Destination IP'] and niaElamData['Destination IP']):
                niaElementTable.add_row(['Destination IP', 'FAIL', elamDict['Destination IP'], niaElamData['Destination IP']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif elamDict['Destination IP'] == niaElamData['Destination IP']:
                niaElementTable.add_row(['Destination IP', 'PASS', elamDict['Destination IP'], niaElamData['Destination IP']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Destination IP', 'FAIL', elamDict['Destination IP'], niaElamData['Destination IP']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Destination IP', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element Source MAC
        # --------------------------------------------
        passedMacWithoutLimiter = []
        observedMacWithoutLimiter = []

        # Check macAddr key is present in Passed Dict
        if 'Source MAC' in elamDict.keys():
            # Modify mac addresses to remove limiters
            elamDict['Source MAC'] = str(elamDict['Source MAC']).upper()
            niaElamData['Source MAC'] = str(niaElamData['Source MAC']).upper()

            for passedMac in elamDict['Source MAC']:
                passedMacWithoutLimiter.append(str(passedMac).translate({ord(i): None for i in ':.-'}))
            for observedMac in niaElamData['Source MAC']:
                observedMacWithoutLimiter.append(str(observedMac).translate({ord(i): None for i in ':.-'}))

            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Source MAC'] and not niaElamData['Source MAC']) \
                    or (not elamDict['Source MAC'] and niaElamData['Source MAC']) \
                    or (len(elamDict['Source MAC']) != len(niaElamData['Source MAC'])):
                niaElementTable.add_row(['Source MAC', 'FAIL', elamDict['Source MAC'], niaElamData['Source MAC']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(passedMacWithoutLimiter,observedMacWithoutLimiter):
                niaElementTable.add_row(['Source MAC', 'PASS', elamDict['Source MAC'], niaElamData['Source MAC']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Source MAC', 'FAIL', elamDict['Source MAC'], niaElamData['Source MAC']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Source MAC', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element Destination MAC
        # --------------------------------------------
        passedMacWithoutLimiter = []
        observedMacWithoutLimiter = []

        # Check macAddr key is present in Passed Dict
        if 'Destination MAC' in elamDict.keys():
            # Modify mac addresses to remove limiters
            elamDict['Destination MAC'] = str(elamDict['Destination MAC']).upper()
            niaElamData['Destination MAC'] = str(niaElamData['Destination MAC']).upper()

            for passedMac in elamDict['Destination MAC']:
                passedMacWithoutLimiter.append(str(passedMac).translate({ord(i): None for i in ':.-'}))
            for observedMac in niaElamData['Destination MAC']:
                observedMacWithoutLimiter.append(str(observedMac).translate({ord(i): None for i in ':.-'}))

            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Destination MAC'] and not niaElamData['Destination MAC']) \
                    or (not elamDict['Destination MAC'] and niaElamData['Destination MAC']) \
                    or (len(elamDict['Destination MAC']) != len(niaElamData['Destination MAC'])):
                niaElementTable.add_row(['Destination MAC', 'FAIL', elamDict['Destination MAC'], niaElamData['Destination MAC']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(passedMacWithoutLimiter,observedMacWithoutLimiter):
                niaElementTable.add_row(['Destination MAC', 'PASS', elamDict['Destination MAC'], niaElamData['Destination MAC']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Destination MAC', 'FAIL', elamDict['Destination MAC'], niaElamData['Destination MAC']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Destination MAC', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element src_vlan
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'src_vlan' in elamDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['src_vlan'] and not niaElamData['src_vlan']) \
                    or (not elamDict['src_vlan'] and niaElamData['src_vlan']):
                niaElementTable.add_row(['src_vlan', 'FAIL', elamDict['src_vlan'], niaElamData['src_vlan']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif elamDict['src_vlan'] == niaElamData['src_vlan']:
                niaElementTable.add_row(['src_vlan', 'PASS', elamDict['src_vlan'], niaElamData['src_vlan']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['src_vlan', 'FAIL', elamDict['src_vlan'], niaElamData['src_vlan']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['src_vlan', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element Source Bridge Domain
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'Source Bridge Domain' in elamDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Source Bridge Domain'] and not niaElamData['Source Bridge Domain']) \
                    or (not elamDict['Source Bridge Domain'] and niaElamData['Source Bridge Domain']):
                niaElementTable.add_row(['Source Bridge Domain', 'FAIL', elamDict['Source Bridge Domain'], niaElamData['Source Bridge Domain']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif elamDict['Source Bridge Domain'] == niaElamData['Source Bridge Domain']:
                niaElementTable.add_row(['Source Bridge Domain', 'PASS', elamDict['Source Bridge Domain'], niaElamData['Source Bridge Domain']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Source Bridge Domain', 'FAIL', elamDict['Source Bridge Domain'], niaElamData['Source Bridge Domain']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Source Bridge Domain', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element Destination Bridge Domain
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'Destination Bridge Domain' in elamDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Destination Bridge Domain'] and not niaElamData['Destination Bridge Domain']) \
                    or (not elamDict['Destination Bridge Domain'] and niaElamData['Destination Bridge Domain']):
                niaElementTable.add_row(['Destination Bridge Domain', 'FAIL', elamDict['Destination Bridge Domain'], niaElamData['Destination Bridge Domain']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif elamDict['Destination Bridge Domain'] == niaElamData['Destination Bridge Domain']:
                niaElementTable.add_row(['Destination Bridge Domain', 'PASS', elamDict['Destination Bridge Domain'], niaElamData['Destination Bridge Domain']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Destination Bridge Domain', 'FAIL', elamDict['Destination Bridge Domain'], niaElamData['Destination Bridge Domain']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Destination Bridge Domain', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element Egress Interface
        # --------------------------------------------
        # Check vni key is present in Passed Dict
        if 'Egress Interface' in elamDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Egress Interface'] and not niaElamData['Egress Interface']) \
                    or (not elamDict['Egress Interface'] and niaElamData['Egress Interface']):
                niaElementTable.add_row(['Egress Interface', 'FAIL', elamDict['Egress Interface'], niaElamData['Egress Interface']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif elamDict['Egress Interface'] == niaElamData['Egress Interface']:
                niaElementTable.add_row(['Egress Interface', 'PASS', elamDict['Egress Interface'], niaElamData['Egress Interface']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Egress Interface', 'FAIL', elamDict['Egress Interface'], niaElamData['Egress Interface']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Egress Interface', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        # --------------------------------------------
        # Validate Element macAddr
        # --------------------------------------------
        # Check macAddr key is present in Passed Dict
        if 'Ingress Interface' in elamDict.keys():
            # Check if either of the passed or observed data should not be empty
            # and size of both the lists are same
            if (elamDict['Ingress Interface'] and not niaElamData['Ingress Interface']) \
                    or (not elamDict['Ingress Interface'] and niaElamData['Ingress Interface']) \
                    or (len(elamDict['Ingress Interface']) != len(niaElamData['Ingress Interface'])):
                niaElementTable.add_row(['Ingress Interface', 'FAIL', elamDict['Ingress Interface'], niaElamData['Ingress Interface']])
                niaVerificationStatus.append(0)
            # Compare the passed and observed data
            elif compare(elamDict['Ingress Interface'],niaElamData['Ingress Interface']):
                niaElementTable.add_row(['Ingress Interface', 'PASS', elamDict['Ingress Interface'], niaElamData['Ingress Interface']])
            # If every check fails then return fail
            else:
                niaElementTable.add_row(['Ingress Interface', 'FAIL', elamDict['Ingress Interface'], niaElamData['Ingress Interface']])
                niaVerificationStatus.append(0)
        # If argument is not passed ignore
        else:
            niaElementTable.add_row(['Ingress Interface', 'ARG NOT PASSED', 'IGNORE', 'IGNORE'])

        niaVerificationMsgs += niaElementTable.draw()

        if 0 in niaVerificationStatus:
            return {'result': 0, 'log': niaVerificationMsgs}
        else:
            return {'result': 1, 'log': niaVerificationMsgs}

    # ====================================================================================================#
    def verifyNIACLI(self, dut, inpDict, dut_mgmt=None):

        # --------------------------------------------
        # Proc level global variables
        # --------------------------------------------
        niaVerificationStatus   = []
        niaVerificationMsgs     = ""

        unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
        unicon_state.add_state_pattern(pattern_list="r'bash-*$'")
        dut.configure("feature bash-shell")

        # --------------------------------------------
        # Build and execute NIA CLI and track nia log
        # --------------------------------------------
        if dut_mgmt is not None:
            # Initiate Tail command
            bash_prompt = ['^(.*)(bash-\\S+|Linux)[#\\$]\\s?$', '^.*--\\s?[Mm]ore\\s?--.*$']
            dut_mgmt.sendline("run bash")
            dut_mgmt.expect(bash_prompt,timeout=60)
            dut_mgmt.sendline('sudo tail -vf /var/sysmgr/work/nia.log > /var/sysmgr/work/temp.txt')
            dut_mgmt.expect([r'.*'], timeout=60)

        # Execute NIA CLI
        niaCLI = self.buildNIACLI(inpDict)
        niaCLIData = json.loads(dut.execute(str(niaCLI), timeout = 1200))

        if dut_mgmt is not None:
            # Terminate Tail command
            bash_prompt = ['^(.*)(bash-\\S+|Linux)[#\\$]\\s?$', '^.*--\\s?[Mm]ore\\s?--.*$']
            dut_mgmt.sendline("\x03")
            dut_mgmt.expect(bash_prompt, timeout=60)
            dut_mgmt.sendline("exit")
            dut_mgmt.expect([r'.*'], timeout=60)

            # Fetching NIA Log and deleting the temp file
            cmd = ["sudo more /var/sysmgr/work/temp.txt | egrep '==>|root'"]
            dut_mgmt.shellexec(cmd, timeout=600)
            cmd = ["sudo rm -rf /var/sysmgr/work/temp.txt"]
            dut_mgmt.shellexec(cmd, timeout=600)

        # --------------------------------------------
        # Perform Initial Check
        # Check Results for NIA state Validator and CC
        # Validate Input parameters
        # --------------------------------------------
        niaInitialCheck = self.validateNIAStatusInputParameters(niaCLIData, inpDict)
        if not niaInitialCheck['result']:
            niaVerificationMsgs += niaInitialCheck['log']
            niaVerificationStatus.append(0)
        else:
            niaVerificationMsgs += niaInitialCheck['log']

        # --------------------------------------------
        # Perform Validation on Element Data
        # --------------------------------------------
        niaElemCheck = self.validateNIAElementData(niaCLIData,inpDict['element_params'])
        if not niaElemCheck['result']:
            niaVerificationMsgs += niaElemCheck['log']
            niaVerificationStatus.append(0)
        else:
            niaVerificationMsgs += niaElemCheck['log']

        # --------------------------------------------
        # Perform Validation on Element ELAM Data
        # --------------------------------------------
        if 'elam_params' in inpDict.keys():
            niaElamCheck = self.validateNIAELAMData(niaCLIData, inpDict['elam_params'])
            if not niaElamCheck['result']:
                niaVerificationMsgs += niaElamCheck['log']
                niaVerificationStatus.append(0)
            else:
                niaVerificationMsgs += niaElamCheck['log']

        # --------------------------------------------
        # Perform Validation on Consistency Checker Data
        # --------------------------------------------
        niaCCCheck = self.validateNIACCData(niaCLIData)
        if not niaCCCheck['result']:
            niaVerificationMsgs += niaCCCheck['log']
            niaVerificationStatus.append(0)
        else:
            niaVerificationMsgs += niaCCCheck['log']

        if 0 in niaVerificationStatus:
            return {'result': 0, 'log': niaVerificationMsgs}
        else:
            return {'result': 1, 'log': niaVerificationMsgs}