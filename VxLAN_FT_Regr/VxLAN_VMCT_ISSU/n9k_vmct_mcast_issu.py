# Example
# -------
#   vMCT MCAST 
#   

from socket import timeout
from pyats import aetest
from common_lib import config_bringup
import yaml
import logging
from pyats.topology import loader
import argparse

# ------------------------------------------------------
# Import and initialize Genie libraries
# ------------------------------------------------------
from genie.conf import Genie
from genie.harness.standalone import run_genie_sdk, GenieStandalone
from genie.conf import Genie

import unicon.statemachine.statemachine
from unicon.eal.dialogs import Statement, Dialog

# pyATS imports

from unicon import Connection
from ats import aetest
from ats.log.utils import banner
from ats.datastructures.logic import Not, And, Or
from ats.easypy import run
from ats.log.utils import banner
from common_lib import bringup_lib
from feature_lib.vxlan import evpn_lib
from feature_lib.vxlan import vxlan_lib
from feature_lib.vxlan import vmct_lib
from feature_lib.vxlan import oam_lib
from pyats.async_ import pcall
from pyats.async_ import Pcall
import time
from common_lib import tgnConfig_lib
from common_lib import tgn_lib
from common_lib import config_lib
from common_lib import config_bringup_test_fex
import re

class CommonSetup(aetest.CommonSetup):

    uid = 'common_setup'
    @aetest.subsection
    def initialize_logging(self, testscript):
        """ Common setup section to initialize logging for script"""

        log = logging.getLogger(__name__)
        log.setLevel(logging.DEBUG)
        testscript.parameters['log'] = log


    @aetest.subsection
    def configBringUp(self,
                       testscript,
                       testbed,
                       log,
                       abs_base_image,
                       abs_target_image,
                       delete_old_images,
                       ):
        testscript.parameters['base_image'] = abs_base_image
        testscript.parameters['target_image'] = abs_target_image
        parser = argparse.ArgumentParser()
        parser.add_argument('--config-file',dest='config_file',type=str)
        args = parser.parse_args()
        config_file = args.config_file
        fp = open(config_file)
        configdict=yaml.safe_load(fp)
        fp.close()
        testscript.parameters['configdict']=configdict
        fail_result=0
        testscript.parameters['fail_result']=fail_result 
        log.info('Getting testbed objects from the testbed file')
        testbed_obj = testbed
        log.info(banner('Executing the Infra bring up'))
        setup_obj = config_bringup_test_fex.configSetup(configdict,testbed_obj,log)
        configdict=config_bringup_test_fex.convertConfig(configdict,testbed_obj)
        testscript.parameters['configdict']=configdict

    @aetest.subsection
    def establish_connections(self,testscript,log,testbed,configdict,steps):
        log.info(banner('Fetch device object'))
        Genie.init(testbed=testbed)
        testscript.parameters["testbed"] = Genie.testbed 
        uut1 = testbed.devices['uut1']
        testscript.parameters['uut1'] = uut1
        uut2 = testbed.devices['uut2']
        testscript.parameters['uut2'] = uut2
        uut3 = testbed.devices['uut3']
        testscript.parameters['uut3'] = uut3
        uut4 = testbed.devices['uut4']
        testscript.parameters['uut4'] = uut4
        uut5 = testbed.devices['uut5']
        testscript.parameters['uut5'] = uut5
        uut6 = testbed.devices['uut6']
        testscript.parameters['uut6'] = uut6

        # declaring vtep list
        vtep_list=[]
        vtep_list=[uut1,uut2,uut3]
        testscript.parameters['vtep_list']=vtep_list
        vpc_list=[]
        vpc_list=[uut1,uut2]
        testscript.parameters['vpc_list']=vpc_list
        vmct_list=[]
        vmct_list=[uut1,uut2,uut4]
        testscript.parameters['vmct_list']=vmct_list
        ngoamAcl_pattern='DATA=0x00008902'
        testscript.parameters['ngoamAcl_pattern']=ngoamAcl_pattern        
        for vtep in vtep_list:
            vtep.connect()
        hdl_list=[]
        configdict_list=[]
        dut_list=[]
        log_list=[]
        for vtep in vtep_list:
                hdl_list.append(vtep)
                dut_list.append(vtep.alias)
                configdict_list.append(configdict)
                log_list.append(log)
        testscript.parameters['hdl_list']=hdl_list
        testscript.parameters['dut_list']=dut_list
        testscript.parameters['configdict_list']=configdict_list
        testscript.parameters['log_list']=log_list

        vpc_hdl_list=[]
        vpc_configdict_list=[]
        vpc_dut_list=[]
        vpc_log_list=[]
        for vtep in vpc_list:
                vpc_hdl_list.append(vtep)
                vpc_dut_list.append(vtep.alias)
                vpc_configdict_list.append(configdict)
                vpc_log_list.append(log)

 
        testscript.parameters['vpc_hdl_list']=vpc_hdl_list
        testscript.parameters['vpc_dut_list']=vpc_dut_list
        testscript.parameters['vpc_configdict_list']=vpc_configdict_list
        testscript.parameters['vpc_log_list']=vpc_log_list

        vmct_hdl_list=[]
        vmct_configdict_list=[]
        vmct_dut_list=[]
        vmct_log_list=[]
 
        for dut in vmct_list:
                vmct_hdl_list.append(dut)
                vmct_dut_list.append(dut.alias)
                vmct_configdict_list.append(configdict)
                vmct_log_list.append(log)

        testscript.parameters['vmct_hdl_list']=vmct_hdl_list
        testscript.parameters['vmct_dut_list']=vmct_dut_list
        testscript.parameters['vmct_configdict_list']=vmct_configdict_list
        testscript.parameters['vmct_log_list']=vmct_log_list


        #declaring test varibales
        vni=1000600
        testscript.parameters['vni']=vni
        stand_host='192.1.51.2'
        testscript.parameters['stand_host']=stand_host
        vrf='evpn_tenant_1000600'
        testscript.parameters['vrf']=vrf
        source_vpc='99.99.99.99'
        testscript.parameters['source_vpc']=source_vpc
        vpc_host='192.1.1.2'
        testscript.parameters['vpc_host']=vpc_host
        source_stand='55.55.55.55'
        testscript.parameters['source_stand']=source_stand
        vpc_sport='2000-2001'
        testscript.parameters['vpc_sport']=vpc_sport
        stand_sport='3000-3001'
        testscript.parameters['stand_sport']=stand_sport
        profile=2
        testscript.parameters['profile']=profile
        profile_oamchannel=3
        testscript.parameters['profile_oamchannel']=profile_oamchannel
        vpc_peer='51.51.51.51'
        testscript.parameters['vpc_peer']=vpc_peer
        stand_peer='40.40.40.40'
        testscript.parameters['stand_peer']=stand_peer
        vpchost_mac='2222.2201.0101'
        testscript.parameters['vpchost_mac']=vpchost_mac
        vpchost_vlan=2
        testscript.parameters['vpchost_vlan']=vpchost_vlan
        standhost_mac='0010.9411.0101'
        testscript.parameters['standhost_mac']=standhost_mac
        standhost_vlan=52
        testscript.parameters['standhost_vlan']=standhost_vlan

#     @aetest.subsection
#     def copy_images_to_devices(self, testbed, testscript, abs_base_image, abs_target_image, delete_old_images):
#         """ Copy Images from Server to devices """

#         BL_base_img_verify_flag         = 0
#         BL_target_img_verify_flag       = 0
#         LEAF_base_img_verify_flag       = 0
#         LEAF_target_img_verify_flag     = 0
        
#         # Remove the boot variables
#         testscript.parameters['uut1'].configure("no boot nxos", timeout=1200)
#         testscript.parameters['uut1'].configure("copy r s", timeout=1200)
#         testscript.parameters['uut2'].configure("no boot nxos", timeout=1200)
#         testscript.parameters['uut2'].configure("copy r s", timeout=1200)

#         # If the flag is set, delete all images
#         if delete_old_images:
#             testscript.parameters['uut1'].execute('delete bootflash:nxos* no')
#             testscript.parameters['uut2'].execute('delete bootflash:nxos* no')

#        #  # Copy the Base Image
#        #  try:
#        #      testscript.parameters['uut1'].shellexec(['rm -rf ~/.ssh/known_hosts'])
#        #      testscript.parameters['uut1'].api.copy_to_device(abs_base_image, 'bootflash:', testbed.servers.tftp.address, 'scp', timeout=1600, vrf='management')
#        #      testscript.parameters['uut2'].shellexec(['rm -rf ~/.ssh/known_hosts'])
#        #      testscript.parameters['uut2'].api.copy_to_device(abs_base_image, 'bootflash:', testbed.servers.tftp.address, 'scp', timeout=1600, vrf='management')
#        #  except Exception as e:
#        #      self.failed('Could not copy Base Images - Exception Seen ->'+str(e), goto=['common_cleanup'])

#         # Copy the Target Image
#         try:
#             testscript.parameters['uut1'].shellexec(['rm -rf ~/.ssh/known_hosts'])
#             testscript.parameters['uut1'].api.copy_to_device(abs_target_image, 'bootflash:', testbed.servers.tftp.address, 'scp', timeout=1600, vrf='management')
#             testscript.parameters['uut2'].shellexec(['rm -rf ~/.ssh/known_hosts'])
#             testscript.parameters['uut2'].api.copy_to_device(abs_target_image, 'bootflash:', testbed.servers.tftp.address, 'scp', timeout=1600, vrf='management')
#         except Exception as e:
#             self.failed('Could not copy Target Images - Exception Seen ->'+str(e), goto=['common_cleanup'])

#         BL_base_img_verify_flag         = testscript.parameters['uut1'].api.verify_file_exists(testscript.parameters['base_image'])
#         BL_target_img_verify_flag       = testscript.parameters['uut1'].api.verify_file_exists(testscript.parameters['target_image'])
#         LEAF_base_img_verify_flag       = testscript.parameters['uut2'].api.verify_file_exists(testscript.parameters['base_image'])
#         LEAF_target_img_verify_flag     = testscript.parameters['uut2'].api.verify_file_exists(testscript.parameters['target_image'])

#         if BL_base_img_verify_flag == 0 or BL_target_img_verify_flag == 0 or LEAF_base_img_verify_flag == 0 or LEAF_target_img_verify_flag == 0:
#             self.failed(reason='Image exists Verification failed')
#         else:
#             self.passed()

class setupConfigVxlan(aetest.Testcase):

    """ Configure VXLAN """
 
    uid = 'setupConfigVxlan'
    @aetest.test
    def ConfigVxlan(self,log,testscript,testbed,vtep_list,configdict):

         log.info(banner('Configuring VXLAN related configs on all VTEPS'))

         setup_result= pcall (vxlan_lib.setupConfigVxlanScale,hdl=testscript.parameters['vtep_list'],dut=testscript.parameters['dut_list'],log=testscript.parameters['log_list'],config_dict=testscript.parameters['configdict_list'])
         if testscript.parameters['fail_result'] not in setup_result:
                 log.info('Vxlan config passed')
         else:
                 log.error('Vxlan config failed')
                 self.failed()

class setupConfigVmct(aetest.Testcase):

    """ Configure VMCT """
 
    uid = 'setupConfigVmct'
    @aetest.test
    def ConfigVmct(self,log,testscript,testbed,vtep_list,configdict):

         log.info(banner('Configuring vMCT'))

         setup_result= pcall (vmct_lib.setupConfigVmct,hdl=testscript.parameters['vmct_list'],dut=testscript.parameters['vmct_dut_list'],log=testscript.parameters['vmct_log_list'],config_dict=testscript.parameters['vmct_configdict_list'])
         if testscript.parameters['fail_result'] not in setup_result:
                 log.info('Vmct config passed')
         else:
                 log.error('Vmct config failed')
                 self.failed()


class setupTgen(aetest.Testcase):
      """Configure TGEN"""

      uid = 'setupTgen'
      @aetest.test
      def SetUpTgen(self,log,testscript,testbed):   
 
        # TGEN Connection 
        tgen=testbed.devices['TG1']
        testscript.parameters['tgen']=tgen
        log.info('TGEN connect')
        tgen.connect()
        time.sleep(90)
                
        log.info('Configuring TGEN device profile')

        result,device_hdl_dict,device_hdl_perVlanDict=tgnConfig_lib.configureDevicesPerVlan(log,tgen,testscript.parameters['configdict']['traffic_config_dict'])

        if result:
                 log.info('Traffic device Config Passed')
                 testscript.parameters['device_hdl_dict']=device_hdl_dict
                 testscript.parameters['device_hdl_perVlanDict']=device_hdl_perVlanDict
        else:
                 log.error('Traffic device Config failed')
                 self.failed() 
        time.sleep(60)
        log.info('configuring Traffic profile in TGEN')
        traffic_result,traffic_handle_dict=tgnConfig_lib.configV4PortBoundTraffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],device_hdl_dict)

        if not traffic_result:
               log.error('Traffic config failed')
               self.failed()
        testscript.parameters['traffic_handle_dict']=traffic_handle_dict

        log.info('configuring BUM Traffic profile in TGEN')
        traffic_bum_result,bum_handle_dict=tgnConfig_lib.configBUMTraffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'])

        if not traffic_bum_result:
               log.error('BUM Traffic config failed')
               self.failed()
        testscript.parameters['bum_handle_dict']=bum_handle_dict


        if re.search('spirent',testscript.parameters['tgen'].type,re.I):
            tgen.stc_apply()
            time.sleep(30)

            tgnConfig_lib.tgn_arp(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict)
            time.sleep(40)
            tgen.stc_apply()
            time.sleep(30)
        log.info('Starting the traffic')
        result=tgnConfig_lib.tgn_traffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict,'start')
        time.sleep(30)
        result=tgnConfig_lib.tgn_traffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict,'stop')
        time.sleep(20)
        result=tgnConfig_lib.tgn_traffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict,'start')
        time.sleep(30)

        if re.search('spirent',testscript.parameters['tgen'].type,re.I):
 
          log.info('Resolving Arp after PortMap')
          tgnConfig_lib.tgn_arp(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'])
          time.sleep(80)
          testscript.parameters['tgen'].stc_apply()
          time.sleep(60)


class VMCTVpcCC(aetest.Testcase):

       """VXLAN VMCT VPC CC"""
       uid = 'VXLAN-VMCT-Vpc-CC'

       @aetest.test
       def vmctMCASTVpcCC(self,log,testscript,testbed):
               result= pcall (vxlan_lib.verifyVMCTCC,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'])
               if testscript.parameters['fail_result'] not in result:
                      log.info('Vmct VPC CC passed')
               else:
                      log.error('Vmct VPC CC failed')
                      self.failed()

class VMCTMCASTVlanCC(aetest.Testcase):

        """VXLAN VMCT MCAST VMCT VLAN CC"""
        uid = 'VXLAN-VMCT-MCAST-Vlan-CC'

        @aetest.test
        def vmctMCASTVlanCC(self,log,testscript,testbed):

               result= pcall (vxlan_lib.verifyVMCTVlanCC,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'])
               if testscript.parameters['fail_result'] not in result:
                        log.info('Vmct Vlan CC passed')
               else:
                     log.error('Vmct Vlan CC failed')
                     self.failed()

class VMCTMCASTFUNC001(aetest.Testcase):

     """VXLAN VMCT MCAST Traffic"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-001'

     @aetest.test
     def vmctMCASTTrafficVpcToStand(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC002(aetest.Testcase):

     """VXLAN VMCT MCAST Traffic"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-002'

     @aetest.test
     def vmctMCASTTrafficStandToVpc(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC003(aetest.Testcase):

     """VXLAN VMCT MCAST Traffic"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-003'

     @aetest.test
     def vmctMCASTTrafficOrphanToVpc(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC004(aetest.Testcase):

     """VXLAN VMCT MCAST Traffic"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-004'

     @aetest.test
     def vmctMCASTTrafficOrphanToOrphan(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()



         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC005(aetest.Testcase):

     """VXLAN VMCT MCAST Traffic"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-005'

     @aetest.test
     def vmctMCASTTrafficOrphanToStand(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()
         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()



         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC006(aetest.Testcase):

     """VXLAN VMCT MCAST Traffic"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-006'

     @aetest.test
     def vmctMCASTTrafficStandToOrphan(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

#***************************************************************************************#
class VMCTMCAST_LXC_ISSU(aetest.Testcase):
    """Verify VMCT Peer LXC ISSU"""
    
    uid = 'VXLAN-VMCT-MCAST-LXC-ISSU-001'

    @aetest.test
    def Verify_Traffic_Before_ISSU(self, testscript, log, testbed):

       log.info('Starting the traffic')
       result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

       log.info('Starting the BUM traffic')
       result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


       time.sleep(300)

       log.info('Verifying traffic ')

       if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
              log.info('The traffic drop is not seen')
       else:
              log.error('The Traffic Drop is more then expected')
              self.failed()


       log.info('Verifying BUM Traffic')

       if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
              log.info('The BUM Traffic working as expected')
       else:
              log.error('The BUM traffic is not working as expected')
              self.failed()
    # =============================================================================================================================#
    @aetest.test
    def CHECK_ISSU_IMPACT(self, testscript):
        """ CHECK ISSU IMPACT """

        # Prepare the ISSU Impact Check command
        issu_impact_cmd = 'sh install all impact nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive'

        # Execute the ISSU Impact command
        impact_output = testscript.parameters['uut1'].execute(issu_impact_cmd, timeout=1200)
        output_split = list(filter(None, impact_output.split('\n')))
        fail_flag = []
        fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                fail_flag.append(0)
                fail_logs += str(log_line) + '\n'
            if re.search('\\d+\\s+yes\\s+(\\S+)\\s+reset', log_line, re.I):
                if not re.search('\\d+\\s+yes\\s+(non-disruptive)\\s+reset', log_line, re.I):
                    fail_flag.append(0)
                    fail_logs += 'The ISSU Impact is reporting Disruptive, Please check\n'
        
        time.sleep(120)

        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_VMCT_LXC_ISSU(self, testscript):
        """ VERIFY_ISSU """
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        # Create ISSU command
        issu_cmd = 'install all nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive' 

        # Perform ISSU
        result, output = testscript.parameters['uut1'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        output_split = list(filter(None, output.split('\n')))
        fail_flag = []
        fail_logs = '\n'
        
        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                if 'Upgrade can no longer be aborted' in log_line:
                    continue
                else:
                    fail_flag.append(0)
                    fail_logs += str(log_line) + '\n'
        
        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")

    @aetest.test
    def Verify_Traffic_After_ISSU(self, testscript,log):

         log.info('Verifying traffic ')
         time.sleep(120)

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()


         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:       
                log.error('The BUM traffic is not working as expected')
                self.failed()
       
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')


# *****************************************************************************************************************************#
class VMCTMCAST_PEER_LXC_ISSU(aetest.Testcase):
    """VERIFY VMCT PEER SECONDARY LXC ISSU"""

    uid = 'VXLAN-VMCT-MCAST-LXC-ISSU-002'

    @aetest.test
    def Verify_Traffic_Before_ISSU(self, testscript, log, testbed):

       log.info('Starting the traffic')
       result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

       log.info('Starting the BUM traffic')
       result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


       time.sleep(300)

       log.info('Verifying traffic ')

       if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
              log.info('The traffic drop is not seen')
       else:
              log.error('The Traffic Drop is more then expected')
              self.failed()


       log.info('Verifying BUM Traffic')

       if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
              log.info('The BUM Traffic working as expected')
       else:
              log.error('The BUM traffic is not working as expected')
              self.failed()

    # =============================================================================================================================#
    @aetest.test
    def CHECK_ISSU_IMPACT(self, testscript):
        """ CHECK ISSU IMPACT """

        # Prepare the ISSU Impact Check command
        issu_impact_cmd = 'sh install all impact nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive'

        # Execute the ISSU Impact command
        impact_output = testscript.parameters['uut2'].execute(issu_impact_cmd, timeout=1200)
        output_split = list(filter(None, impact_output.split('\n')))
        fail_flag = []
        fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                fail_flag.append(0)
                fail_logs += str(log_line) + '\n'
            if re.search('\\d+\\s+yes\\s+(\\S+)\\s+reset', log_line, re.I):
                if not re.search('\\d+\\s+yes\\s+(non-disruptive)\\s+reset', log_line, re.I):
                    fail_flag.append(0)
                    fail_logs += 'The ISSU Impact is reporting Disruptive, Please check\n'
        
        time.sleep(120)

        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_VMCT_PEER_SECONDARY_LXC_ISSU(self, testscript):
        """ VERIFY_ISSU """
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        # Create ISSU command
        issu_cmd = 'install all nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive' 

        # Perform ISSU
        result, output = testscript.parameters['uut2'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        output_split = list(filter(None, output.split('\n')))
        fail_flag = []
        fail_logs = '\n'
        
        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|CPU Hog|malloc|core dump|mts_send|redzone', log_line, re.I):
                if 'Upgrade can no longer be aborted' in log_line:
                    continue
                else:
                    fail_flag.append(0)
                    fail_logs += str(log_line) + '\n'
        
        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")
    
    @aetest.test
    def Verify_Traffic_after_ISSU(self, testscript,log):

         log.info('Verifying traffic ')
         time.sleep(120)

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()


         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:       
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')
# *****************************************************************************************************************************#

class VMCTMCASTFUNC007(aetest.Testcase):

     """VXLAN PV Routing L2 vni Add/Delete"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-007'

     @aetest.test
     def vmctMCASTL2VniDeleteAdd(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()



         log.info('Deleting and Adding the L2 VNI configured')

         result= pcall (vxlan_lib.DeleteAddVxlanL2Vni,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Vxlan Delete and Add L2 VNI passed')
         else:
                 log.error('Vxlan Delete and Add L2 VNI failed')
                 self.failed()

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC008(aetest.Testcase):

     """VXLAN VMCT MCAST  L3 vni Add/Delete"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-008'

     @aetest.test
     def vmctMCASTL3VniDeleteAdd(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Deleting and Adding the L3 VNI configured')

         result= pcall (vxlan_lib.DeleteAddVxlanL3Vni,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Vxlan Delete and Add L3 VNI  passed')
         else:
                 log.error('Vxlan Delete and Add L3 VNI failed')
                 self.failed()

         time.sleep(240)

         log.info('Verifying traffic after Deleting and Adding the L3 VNI ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC009(aetest.Testcase):

     """Delete and Add loopback int of NVE"""
     uid = 'VXLAN-VMCT-MCAST-FUNC-009'

     @aetest.test
     def vmctMCASTAddDeleteLoopback(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Delete and Add the Loopback interface of Nve')

         result= pcall (vxlan_lib.AddDeleteNveLoopback,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('NVE loopback remove and add passed')
         else:
                 log.error('NVE loopback remove and add failed')
                 self.failed()

         time.sleep(240)

         log.info('Verifying traffic after Remove and Add of Loopback interface of Nve')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC010(aetest.Testcase):

     """Flap BGP """

     uid = 'VXLAN-VMCT-MCAST-FUNC-010'

     @aetest.test
     def vmctMCASTFlapBgp(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the BGP in all vtep')
         for vtep in testscript.parameters['vtep_list']:
                cfg=''
                for as_no in testscript.parameters['configdict']['bgp_config_dict'][vtep.alias]:
                      cfg+='''router bgp {0}
                              shut
                              no shut
                           '''.format(as_no)
                vtep.configure(cfg)

         time.sleep(240)
         log.info('Verifying traffic after flapping BGP')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC011(aetest.Testcase):

     """Flap BGP EVPN Neighbors"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-011'

     @aetest.test
     def vmctMCASTFlapBgpEvpnNeighbors(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping BGP EVPN neighbors')
         for vtep in testscript.parameters['vtep_list']:
                cfg=''
                for as_no in testscript.parameters['configdict']['bgp_config_dict'][vtep.alias]:
                      for nei in testscript.parameters['configdict']['bgp_config_dict'][vtep.alias][as_no]['default']['neighbors']['ipv4']:
                     
                           cfg+='''router bgp {0}
                                   neighbor {1}
                                   shut
                                   no shut
                                 '''.format(as_no,nei)
                vtep.configure(cfg)

         time.sleep(240)

         log.info('Verifying traffic after flapping BGP neighbor')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC012(aetest.Testcase):

     """Clear BGP """

     uid = 'VXLAN-VMCT-MCAST-FUNC-012'

     @aetest.test
     def vmctMCASTClearBgp(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

 
         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('clear BGP routes')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear ip bgp *')

         time.sleep(240)
         log.info('Verifying Traffic after clear BGP')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC013(aetest.Testcase):

     """Clear ip route """

     uid = 'VXLAN-VMCT-MCAST-FUNC-013'

     @aetest.test
     def vmctMCASTClearRoute(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

 
         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('clear ip routes')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear ip route *')

         time.sleep(240)

         log.info('Verifying Traffic after clearing all routes')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC014(aetest.Testcase):

     """Clear ip mroute """

     uid = 'VXLAN-VMCT-MCAST-FUNC-014'

     @aetest.test
     def vmctMCASTClearMRoute(self,log,testscript,testbed):


         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()



         log.info('clear ip mroutes')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear ip mroute *')

         time.sleep(240)
         log.info('Verifying Traffic after clearing all mroutes')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC015(aetest.Testcase):

     """Clear ip arp """

     uid = 'VXLAN-VMCT-MCAST-FUNC-015'

     @aetest.test
     def vmctMCASTClearArp(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('clear ip arp')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear ip arp')

         time.sleep(240)
         log.info('Verifying Traffic after clearing all ARP')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC016(aetest.Testcase):

     """Clear mac address """

     uid = 'VXLAN-VMCT-MCAST-FUNC-016'

     @aetest.test
     def vmctMCASTClearMac(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('clear mac Address Table')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear mac address-table dynamic ')

         time.sleep(240)
         log.info('Verifying Traffic after clearing all MAC')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC017(aetest.Testcase):

     """Flap Uplinks"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-017'

     @aetest.test
     def vmctMCASTFlapUplink(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Flapping the Uplink')
         result= pcall (vxlan_lib.flapUplink,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping uplink passed')
         else:
                 log.error('Flapping uplink failed')
                 self.failed()

         time.sleep(300)

         log.info('Verifying traffic after Uplink Flap')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC018(aetest.Testcase):

     """Flap Access links"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-018'

     @aetest.test
     def vmctMCASTFlapAccesslink(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(300)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the Access link')
         result= pcall (vxlan_lib.flapAccesslink,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping Access link passed')
         else:
                 log.error('Flapping Access link failed')
                 self.failed()

         if re.search('spirent',testscript.parameters['tgen'].type,re.I):
           log.info('Resolving Arp after Flap')
           tgnConfig_lib.tgn_arp(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'])
           time.sleep(60)
           testscript.parameters['tgen'].stc_apply()
         time.sleep(300)

         log.info('Verifying traffic after Access link Flap')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC019(aetest.Testcase):

     """Flap VPC PO Access links"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-019'

     @aetest.test
     def vmctMCASTFlapVpcPoAccess(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(300)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the VPC PO Access link')
         result= pcall (vxlan_lib.flapVPCPOlink,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'],dut=testscript.parameters['vpc_dut_list'],configDict=testscript.parameters['vpc_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping VPC PO Access link passed')
         else:
                 log.error('Flapping VPC PO Access link failed')
                 self.failed()

         if re.search('spirent',testscript.parameters['tgen'].type,re.I):
           log.info('Resolving Arp after Flap')
           tgnConfig_lib.tgn_arp(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'])
           time.sleep(60)
           testscript.parameters['tgen'].stc_apply()
         time.sleep(300)

         log.info('Verifying traffic after VPC PO Access link Flap')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()
         log.info('Shutting the PO on UUT1')
         action='shut'
         if vxlan_lib.shutUnshutVPCPOlink(log,testscript.parameters['uut1'],testscript.parameters['uut1'].alias,testscript.parameters['configdict'],action):
                   log.info('Shutting of PO Access is sucess')
         else:
                   log.error('Shutting of PO Access failed')
                   self.failed()

         time.sleep(60)
         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
              #   self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
              #   self.failed()
         log.info('Unshutting the Access PO on UUT1')
         action='unshut'
         if vxlan_lib.shutUnshutVPCPOlink(log,testscript.parameters['uut1'],testscript.parameters['uut1'].alias,testscript.parameters['configdict'],action):
                   log.info('UnShutting of PO Access is sucess')
         else:
                   log.error('UnShutting of PO Access failed')
                   self.failed()
         time.sleep(60)
         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Shutting the PO on UUT2')
         action='shut'
         if vxlan_lib.shutUnshutVPCPOlink(log,testscript.parameters['uut2'],testscript.parameters['uut2'].alias,testscript.parameters['configdict'],action):
                   log.info('Shutting of PO Access is sucess')
         else:
                   log.error('Shutting of PO Access failed')
                   self.failed()
         time.sleep(60)
         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
              #   self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
              #   self.failed()
         log.info('Unshutting the Access PO on UUT1')
         action='unshut'
         if vxlan_lib.shutUnshutVPCPOlink(log,testscript.parameters['uut2'],testscript.parameters['uut2'].alias,testscript.parameters['configdict'],action):
                   log.info('UnShutting of PO Access is sucess')
         else:
                   log.error('UnShutting of PO Access failed')
                   self.failed()
         time.sleep(60)
         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()
 
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC020(aetest.Testcase):

     """Flap VPC PO Member Access links"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-020'

     @aetest.test
     def vmctMCASTFlapVpcPoMemAccess(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(300)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the VPC PO Memeber Access link')
         result= pcall (vxlan_lib.flapVPCPOMemlink,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'],dut=testscript.parameters['vpc_dut_list'],configDict=testscript.parameters['vpc_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping VPC PO Memeber Access link passed')
         else:
                 log.error('Flapping VPC PO Memeber Access link failed')
                 self.failed()

         if re.search('spirent',testscript.parameters['tgen'].type,re.I):
           log.info('Resolving Arp after Flap')
           tgnConfig_lib.tgn_arp(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'])
           time.sleep(60)
           testscript.parameters['tgen'].stc_apply()
 
         time.sleep(300)

         log.info('Verifying traffic after VPC PO Memeber Access link Flap')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Shutting the PO on UUT1')
         action='shut'
         if vxlan_lib.shutUnshutVPCPOMemlink(log,testscript.parameters['uut1'],testscript.parameters['uut1'].alias,testscript.parameters['configdict'],action):
                   log.info('Shutting of PO Access is sucess')
         else:
                   log.error('Shutting of PO Access failed')
                   self.failed()
         time.sleep(40)
         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
              #   self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
              #   self.failed()
         log.info('Unshutting the Access PO on UUT1')
         action='unshut'
         if vxlan_lib.shutUnshutVPCPOMemlink(log,testscript.parameters['uut1'],testscript.parameters['uut1'].alias,testscript.parameters['configdict'],action):
                   log.info('UnShutting of PO Access is sucess')
         else:
                   log.error('UnShutting of PO Access failed')
                   self.failed()
         time.sleep(60)
         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Shutting the PO on UUT2')
         action='shut'
         if vxlan_lib.shutUnshutVPCPOMemlink(log,testscript.parameters['uut2'],testscript.parameters['uut2'].alias,testscript.parameters['configdict'],action):
                   log.info('Shutting of PO Access is sucess')
         else:
                   log.error('Shutting of PO Access failed')
                   self.failed()
         time.sleep(60)
         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
              #   self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
              #   self.failed()
         log.info('Unshutting the Access PO on UUT2')
         action='unshut'
         if vxlan_lib.shutUnshutVPCPOMemlink(log,testscript.parameters['uut2'],testscript.parameters['uut2'].alias,testscript.parameters['configdict'],action):
                   log.info('UnShutting of PO Access is sucess')
         else:
                   log.error('UnShutting of PO Access failed')
                   self.failed()
         time.sleep(60)
         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()
 

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC021(aetest.Testcase):

     """Nve Flap """

     uid = 'VXLAN-VMCT-MCAST-FUNC-021'

     @aetest.test
     def vmctMCASTNveFlap(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(300)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Nve Flap')
         for vtep in testscript.parameters['vtep_list']:
                 cfg=''
                 cfg+='''interface nve1
                         shut
                         no shut
                      '''
                 out=vtep.configure(cfg)
                 if re.search('error|invalid',out,re.I):
                    log.error(f'Nve failed for VTEP {vtep}')
                    self.failed()

         time.sleep(300)
         log.info('Verifying Traffic after NVE Flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC022(aetest.Testcase):

     """Nve source interface Flap """

     uid = 'VXLAN-VMCT-MCAST-FUNC-022'

     @aetest.test
     def vmctMCASTNveSrcIntFlap(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(80)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Nve Source Int Flap')
         result= pcall (vxlan_lib.flapNveSourceInt,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Nve Source Int Flap passed')
         else:
                 log.error('Nve Source Int Flap failed')
                 self.failed()

         time.sleep(300)
         log.info('Verifying Traffic after NVE Flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCAST_ISSU(aetest.Testcase):
    """Verify VMCT Peer ISSU"""
    
    uid = 'VXLAN-VMCT-MCAST-ISSU-001'

    @aetest.test
    def Verify_Traffic_Before_ISSU(self, testscript, log, testbed):

       log.info('Starting the traffic')
       result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

       log.info('Starting the BUM traffic')
       result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


       time.sleep(300)

       log.info('Verifying traffic ')

       if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
              log.info('The traffic drop is not seen')
       else:
              log.error('The Traffic Drop is more then expected')
              self.failed()


       log.info('Verifying BUM Traffic')

       if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
              log.info('The BUM Traffic working as expected')
       else:
              log.error('The BUM traffic is not working as expected')
              self.failed()
    # =============================================================================================================================#
    @aetest.test
    def CHECK_ISSU_IMPACT(self, testscript):
        """ CHECK ISSU IMPACT """

        # Prepare the ISSU Impact Check command
        issu_impact_cmd = 'sh install all impact nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive'

        # Execute the ISSU Impact command
        impact_output = testscript.parameters['uut1'].execute(issu_impact_cmd, timeout=1200)
        output_split = list(filter(None, impact_output.split('\n')))
        fail_flag = []
        fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                fail_flag.append(0)
                fail_logs += str(log_line) + '\n'
            if re.search('\\d+\\s+yes\\s+(\\S+)\\s+reset', log_line, re.I):
                if not re.search('\\d+\\s+yes\\s+(non-disruptive)\\s+reset', log_line, re.I):
                    fail_flag.append(0)
                    fail_logs += 'The ISSU Impact is reporting Disruptive, Please check\n'
        
        time.sleep(120)

        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")

    # =============================================================================================================================#
    @aetest.test
    def VMCT_VERIFY_ISSU(self, testscript):
        """ VERIFY_ISSU """
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        # Create ISSU command
        issu_cmd = 'install all nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive' 

        # Perform ISSU
        result, output = testscript.parameters['uut1'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        output_split = list(filter(None, output.split('\n')))
        fail_flag = []
        fail_logs = '\n'
        
        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                if 'Upgrade can no longer be aborted' in log_line:
                    continue
                else:
                    fail_flag.append(0)
                    fail_logs += str(log_line) + '\n'
        
        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")

    @aetest.test
    def Verify_Traffic_After_ISSU(self, testscript,log):

         log.info('Verifying traffic ')
         time.sleep(120)

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()


         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:       
                log.error('The BUM traffic is not working as expected')
                self.failed()
       
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')


# *****************************************************************************************************************************#
class VMCTMCAST_PEER_ISSU(aetest.Testcase):
    """VERIFY VMCT PEER SECONDARY ISSU"""

    uid = 'VXLAN-VMCT-MCAST-ISSU-002'

    @aetest.test
    def Verify_Traffic_Before_ISSU(self, testscript, log, testbed):

       log.info('Starting the traffic')
       result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

       log.info('Starting the BUM traffic')
       result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


       time.sleep(300)

       log.info('Verifying traffic ')

       if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
              log.info('The traffic drop is not seen')
       else:
              log.error('The Traffic Drop is more then expected')
              self.failed()


       log.info('Verifying BUM Traffic')

       if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
              log.info('The BUM Traffic working as expected')
       else:
              log.error('The BUM traffic is not working as expected')
              self.failed()

    # =============================================================================================================================#
    @aetest.test
    def CHECK_ISSU_IMPACT(self, testscript):
        """ CHECK ISSU IMPACT """

        # Prepare the ISSU Impact Check command
        issu_impact_cmd = 'sh install all impact nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive'

        # Execute the ISSU Impact command
        impact_output = testscript.parameters['uut2'].execute(issu_impact_cmd, timeout=1200)
        output_split = list(filter(None, impact_output.split('\n')))
        fail_flag = []
        fail_logs = '\n'

        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                fail_flag.append(0)
                fail_logs += str(log_line) + '\n'
            if re.search('\\d+\\s+yes\\s+(\\S+)\\s+reset', log_line, re.I):
                if not re.search('\\d+\\s+yes\\s+(non-disruptive)\\s+reset', log_line, re.I):
                    fail_flag.append(0)
                    fail_logs += 'The ISSU Impact is reporting Disruptive, Please check\n'
        
        time.sleep(120)

        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")

    # =============================================================================================================================#
    @aetest.test
    def VERIFY_VMCT_PEER_SECONDARY_ISSU(self, testscript):
        """ VERIFY_ISSU """
        
        # Establish dialogs for running ISSU command
        dialog = Dialog([
            Statement(pattern=r'Do you want to continue with the installation \(y/n\)\?',
                      action='sendline(y)',
                      loop_continue=True,
                      continue_timer=True),
        ])
        
        # Create ISSU command
        issu_cmd = 'install all nxos bootflash:'+str(testscript.parameters['target_image'])+' non-disruptive' 

        # Perform ISSU
        result, output = testscript.parameters['uut2'].reload(reload_command=issu_cmd, prompt_recovery=True, dialog=dialog, timeout=2000, return_output=True)
        output_split = list(filter(None, output.split('\n')))
        fail_flag = []
        fail_logs = '\n'
        
        # Process logs for any failure reasons
        for log_line in output_split:
            if re.search('CRASHED|fail|CPU Hog|malloc|core dump|mts_send|redzone|error', log_line, re.I):
                if 'Upgrade can no longer be aborted' in log_line:
                    continue
                else:
                    fail_flag.append(0)
                    fail_logs += str(log_line) + '\n'
        
        # Reporting
        if 0 in fail_flag:
            self.failed(reason=fail_logs)
        else:
            self.passed(reason="Upgrade successful")
    
    @aetest.test
    def Verify_Traffic_after_ISSU(self, testscript,log):

         log.info('Verifying traffic ')
         time.sleep(120)

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()


         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:       
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')
# *****************************************************************************************************************************#

class VMCTMCASTFUNC023(aetest.Testcase):

     """Flap VPC PO Access links Primary and Secondary"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-023'

     @aetest.test
     def vmctMCASTFlapVpcPoAccess(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(80)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the VPC PO Access link')
         result= pcall (vxlan_lib.flapVPCPOlink,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'],dut=testscript.parameters['vpc_dut_list'],configDict=testscript.parameters['vpc_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping VPC PO Access link passed')
         else:
                 log.error('Flapping VPC PO Access link failed')
                 self.failed()
         if re.search('spirent',testscript.parameters['tgen'].type,re.I):
           log.info('Resolving Arp after Flap')
           tgnConfig_lib.tgn_arp(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'])
           time.sleep(60)
           testscript.parameters['tgen'].stc_apply()
         time.sleep(300)

         log.info('Verifying traffic after VPC PO Access link Flap')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC024(aetest.Testcase):

     """Flap Vxlan VRF"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-024'

     @aetest.test
     def vmctMCASTFlapVrf(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the VXLAN VRF')
         result= pcall (vxlan_lib.flapVxlanVrf,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'],dut=testscript.parameters['vpc_dut_list'],configDict=testscript.parameters['vpc_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping of VXLAN VRF passed')
         else:
                 log.error('Flapping of VXLAN VRF failed')
                 self.failed()

         time.sleep(240)
         log.info('Verifying traffic after Vxlan VRF')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC025(aetest.Testcase):

     """Flap L2 VNI SVI"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-025'

     @aetest.test
     def vmctMCASTFlapL2VniSvi(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the L2 Vni Svi')
         result= pcall (vxlan_lib.flapL2VniSvi,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping of L2 Vni Svi passed')
         else:
                 log.error('Flapping of L2 Vni Svi failed')
                 self.failed()

         time.sleep(240)

         log.info('Verifying traffic after flapping L2 Vni Svi')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC026(aetest.Testcase):

     """Flap L3 VNI SVI"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-026'

     @aetest.test
     def vmctMCASTFlapL3VniSvi(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the L3 Vni Svi')
         result= pcall (vxlan_lib.flapL3VniSvi,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping of L3 Vni Svi passed')
         else:
                 log.error('Flapping of L3 Vni Svi failed')
                 self.failed()
         time.sleep(240)

         log.info('Verifying traffic after flapping L3 Vni Svi')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC027(aetest.Testcase):

     """Remove and Add PortType Fabric from uplink"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-027'

     @aetest.test
     def vmctMCASTRemoveAddPortTypefabric(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Remove and Add Porttype Fabric from uplink')
         result= pcall (vxlan_lib.RemoveAddPortTypeFabric,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'],dut=testscript.parameters['vpc_dut_list'],configDict=testscript.parameters['vpc_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Remove and Add Porttype Fabric passed')
         else:
                 log.error('Remove and Add Porttype Fabric failed')
                 self.failed()

         time.sleep(300)

         log.info('Verifying traffic after Remove and Add Port type Fabric from uplink')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC028(aetest.Testcase):

     """Delete and Add vpc id in VPC PO access link"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-028'

     @aetest.test
     def vmctMCASTDeleteAddVpcId(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Remove and Add Vpc Id from VPC PO access link')
         result= pcall (vxlan_lib.deleteAddVpcId,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'],dut=testscript.parameters['vpc_dut_list'],configDict=testscript.parameters['vpc_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Remove and Add Vpc Id from VPC PO access link passed')
         else:
                 log.error('Remove and Add Vpc Id from VPC PO access link failed')
                 self.failed()

         time.sleep(300)

         log.info('Verifying traffic after Remove and Add Vpc Id from VPC PO access link')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC029(aetest.Testcase):

     """Suspend and Activate Vxlan Vlan"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-029'

     @aetest.test
     def vmctMCASTSuspendActivateVlan(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Suspend and Activate Vxlan Vlan')
         result= pcall (vxlan_lib.SuspendActiveVxlanVlan,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Suspend and Activate Vxlan passed')
         else:
                 log.error('Suspend and Activate Vxlan failed')
                 self.failed()

         time.sleep(300)

         log.info('Verifying traffic after Suspend and Activate Vxlan Vlan')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC030(aetest.Testcase):

     """Shutting uplink on one of the peer vMCT"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-030'

     @aetest.test
     def vmctMCASTShutUplink(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Shuting the uplink on UUT1')
         action='shut'
         result= vxlan_lib.shutUnshutPort(log,testscript.parameters['uut1'],testscript.parameters['uut1'].alias,testscript.parameters['configdict'],action)

         if result:
                 log.info('Uplinks shut on UUT1 Passed ')
         else:
                 log.error(' Uplinks shut on UUT1 failed')
                 self.failed()

         time.sleep(60)

         #log.info('Verifying traffic after shut on UUT1')

         #if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
         #       log.info('The traffic drop is not seen')
         #else:
         #       log.error('The Traffic Drop is more then expected')
         #       self.failed()

         #log.info('Verifying BUM Traffic')

         #if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'-intDown 1' ):
         #       log.info('The BUM Traffic working as expected')
         #else:
         #       log.error('The BUM traffic is not working as expected')
         #       self.failed()

         log.info('Un Shut the uplink on UUT1')
         action='no shut'
         result= vxlan_lib.shutUnshutPort(log,testscript.parameters['uut1'],testscript.parameters['uut1'].alias,testscript.parameters['configdict'],action)

         if result:
                 log.info('Uplinks unshut on UUT1 Passed ')
         else:
                 log.error(' Uplinks unshut on UUT1 failed')
                 self.failed()

         time.sleep(250)

         log.info('Verifying traffic after unshut on UUT1')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC031(aetest.Testcase):

     """Shutting uplink on secondary peer vMCT"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-031'

     @aetest.test
     def vmctMCASTShutUplinkSec(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Shuting the uplink on UUT2')
         action='shut'
         result= vxlan_lib.shutUnshutPort(log,testscript.parameters['uut2'],testscript.parameters['uut2'].alias,testscript.parameters['configdict'],action)

         if result:
                 log.info('Uplinks shut on UUT2 Passed ')
         else:
                 log.error(' Uplinks shut on UUT2 failed')
                 self.failed()

         #time.sleep(60)

         #log.info('Verifying traffic after shut on UUT1')

         #if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
         #       log.info('The traffic drop is not seen')
         #else:
         #       log.error('The Traffic Drop is more then expected')
         #       self.failed()

         #log.info('Verifying BUM Traffic')

         #if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'-intDown 1' ):
         #       log.info('The BUM Traffic working as expected')
         #else:
         #       log.error('The BUM traffic is not working as expected')
         #       self.failed()

         log.info('Un Shut the uplink on UUT1')
         action='no shut'
         result= vxlan_lib.shutUnshutPort(log,testscript.parameters['uut2'],testscript.parameters['uut2'].alias,testscript.parameters['configdict'],action)

         if result:
                 log.info('Uplinks unshut on UUT2 Passed ')
         else:
                 log.error(' Uplinks unshut on UUT2 failed')
                 self.failed()

         time.sleep(250)

         log.info('Verifying traffic after unshut on UUT1')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC032(aetest.Testcase):

     """Flap vMCT Keepalive link"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-032'

     @aetest.test
     def vmctMCASTKeepalivelink(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Flapping the Keppalive link')
         result= pcall (vxlan_lib.flapvMCTKeepalivelink,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'],dut=testscript.parameters['vpc_dut_list'],configDict=testscript.parameters['vpc_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping  Keppalive link passed')
         else:
                 log.error('Flapping Keppalive link failed')
                 self.failed()

         time.sleep(300)

         log.info('Verifying traffic after Keppalive link Flap')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')



class VMCTMCASTFUNC033(aetest.Testcase):

     """Multiple Flap Uplinks"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-033'

     @aetest.test
     def vmctMCASTMultipleFlapUplink(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(240)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Flapping the Uplink multiple times')
         seq_no=1
         count=10
         while seq_no <=count:
             result= pcall (vxlan_lib.flapUplink,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

             if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping uplink passed')
             else:
                 log.error('Flapping uplink failed')
                 self.failed()
             seq_no+=1
         time.sleep(300)

         log.info('Verifying traffic after Uplink Flap')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC034(aetest.Testcase):

     """Multiple Flap Access links"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-034'

     @aetest.test
     def vmctMCASTMultipleFlapAccesslink(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(300)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()


         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Flapping the Access link Multiple times')
         seq_no=1
         count=10
         while seq_no <=count:
 
             result= pcall (vxlan_lib.flapAccesslink,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

             if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping Access link passed')
             else:
                 log.error('Flapping Access link failed')
                 self.failed()
             seq_no+=1

         if re.search('spirent',testscript.parameters['tgen'].type,re.I):
           log.info('Resolving Arp after Flap')
           tgnConfig_lib.tgn_arp(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'])
           time.sleep(60)
           testscript.parameters['tgen'].stc_apply()
         time.sleep(300)

         log.info('Verifying traffic after Access link Flap')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC037(aetest.Testcase):

     """Reload vMCT Peer"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-035'

     @aetest.test
     def vmctMCASTreloadPeer(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(300)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Change boot variable to base image')

         boot_cmd = 'boot nxos bootflash:'+str(testscript.parameters['base_image'])+'' 
         testscript.parameters['uut1'].configure(boot_cmd,timeout=300)
         testscript.parameters['uut1'].configure('boot mode lxc')
         
         log.info('Reload vMct Peer')

         testscript.parameters['uut1'].execute('copy r s',timeout=120)
         testscript.parameters['uut1'].reload(prompt_recovery=True, timeout=1200)
         time.sleep(350)
           

         log.info('Verifying traffic after vMCT peer reload')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')


class VMCTMCASTFUNC038(aetest.Testcase):

     """Reload vMCT Peer Secondary"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-036'

     @aetest.test
     def vmctMCASTreloadSecondaryPeer(self,log,testscript,testbed):

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(300)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()
         

         log.info('Change boot variable to base image and change lxc mode')

         boot_cmd = 'boot nxos bootflash:'+str(testscript.parameters['base_image'])+'' 
         testscript.parameters['uut2'].configure(boot_cmd,timeout=300)
         testscript.parameters['uut2'].configure('boot mode lxc')
         
         log.info('Reload vMct Secondary Peer')

         testscript.parameters['uut2'].execute('copy r s',timeout=120)
         testscript.parameters['uut2'].reload(prompt_recovery=True, timeout=1200)
         time.sleep(350)
       
         log.info('Verifying traffic after vMCT peer reload')

         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

