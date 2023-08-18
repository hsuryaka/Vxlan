# Example
# -------
#   vMCT MCAST 
#   

from pyats import aetest
from common_lib import config_bringup
import yaml
import logging
from pyats.topology import loader
import argparse

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
                       ):

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

class VMCTMCASTOAMFUNC033(aetest.Testcase):

      """ Verify vMCT AA OAM Ping using vni option """

      uid = 'VMCT-MCAST-OAM-FUNC-033'
      @aetest.test
      def vmctMCASTpingOamHostIpVni(self,log,testscript,testbed,vtep_list):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info('Verify the Ping from VPC to standalone VTEP')

         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC034(aetest.Testcase):

      """ Verify vMCT AA OAM Ping using different interface  """

      uid = 'VMCT-MCAST-OAM-FUNC-034'
      @aetest.test
      def vMCTAApingOamHostIpVniEgress(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')
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


         log.info('Verify the Ping from VPC to standalone VTEP via Eth uplink')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -egress {2} -source {3}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC via Eth uplink')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -egress {2} -source {3}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['eth'],testscript.parameters['source_stand'])):

               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP via PO uplink')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -egress {2} -source {3}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['PO'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected via PO'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working via PO')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC via PO uplink')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -egress {2} -source {3}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected via PO')
         else:
               log.error('Ping to remote host from standalone to VPC is not workingvia PO')
               self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC035(aetest.Testcase):

      """ Verify vMCT Fex AA OAM Ping using vrf option """

      uid = 'VMCT-MCAST-OAM-FUNC-035'
      @aetest.test
      def vMCTAApingOamHostIpVrf(self,log,testscript,testbed,vtep_list):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')
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


         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC036(aetest.Testcase):

      """ Verify VMCT MCAST OAM Ping using Sport """

      uid = 'VMCT-MCAST-OAM-FUNC-036'
      @aetest.test
      def vMCTFexAApingOamHostIpVniSport(self,log,testscript,testbed,vtep_list):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -sport {3} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'],testscript.parameters['vpc_sport'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -sport {3} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'],testscript.parameters['stand_sport'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC037(aetest.Testcase):

      """ Verify vMCT MCAST OAM Ping using different interface via VRF option  """

      uid = 'VMCT-MCAST-OAM-FUNC-037'
      @aetest.test
      def vMctFexAApingOamHostIpVrfEgress(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info('Verify the Ping from VPC to standalone VTEP via Eth uplink')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -egress {2} -source {3}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC via Eth uplink')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -egress {2} -source {3}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['eth'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP via PO uplink')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -egress {2} -source {3}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['PO'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected via PO'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working via PO')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC via PO uplink')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -egress {2} -source {3}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected via PO')
         else:
               log.error('Ping to remote host from standalone to VPC is not workingvia PO')
               self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC038(aetest.Testcase):

      """ Verify vMCT MCAST OAM Ping using Sport via vrf option"""

      uid = 'VMCT-MCAST-OAM-FUNC-038'
      @aetest.test
      def vMctFexAApingOamHostIpVrfSport(self,log,testscript,testbed):
         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -sport {3} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'],testscript.parameters['vpc_sport'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -sport {3} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'],testscript.parameters['stand_sport'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC039(aetest.Testcase):

      """ Verify OAM Ping using profile """

      uid = 'VMCT-MCAST-OAM-FUNC-039'
      @aetest.test
      def vMctFexAApingOamHostIPProfile(self,log,testscript,testbed,vtep_list):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')
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

         log.info(banner('Configuring NGOAM profile'))
         oam_lib.configNgoamProfile(testscript.parameters['configdict']['oam_config_dict']['uut1']['profile1'],testscript.parameters['uut1'],log)
         oam_lib.configNgoamProfile(testscript.parameters['configdict']['oam_config_dict']['uut3']['profile1'],testscript.parameters['uut3'],log)
         
         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -profile {3} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'],testscript.parameters['profile'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -profile {3} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'],testscript.parameters['profile'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC040(aetest.Testcase):

      """ Verify OAM Ping using vni option with traffic Flow"""

      uid = 'VMCT-MCAST-OAM-FUNC-040'
      @aetest.test
      def vMctMCASTpingOamHostIpVniTraffic(self,log,testscript,testbed,vtep_list):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


 
         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Verifying traffic after NGOAM Ping ')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')
         time.sleep(30) 
 
class VMCTMCASTOAMFUNC041(aetest.Testcase):

      """ Verify OAM Pathtrace to NVE  """

      uid = 'VMCT-MCAST-OAM-FUNC-041'
      @aetest.test
      def vMctMCASTPathtraceNve (self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1}'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1}'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC042(aetest.Testcase):

      """ Verify OAM Pathtrace to NVE with traffic"""

      uid = 'VMCT-MCAST-OAM-FUNC-042'
      @aetest.test
      def vMctMCASTPathtraceNveTraffic (self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1}'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1}'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()
         log.info('Verifying traffic after NGOAM Pathtrace ')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')
 
class VMCTMCASTOAMFUNC043(aetest.Testcase):

      """ Verify OAM Pathtrace to NVE with Verbose  """

      uid = 'VMCT-MCAST-OAM-FUNC-043'
      @aetest.test
      def vMctMCASTPathtraceNve (self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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



         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC044(aetest.Testcase):

      """ Verify OAM Pathtrace with Req-stat to NVE  """

      uid = 'VMCT-MCAST-OAM-FUNC-044'
      @aetest.test
      def vMctMCASTPathtraceNveReqStat (self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtraceReqStat(testscript.parameters['uut1'],log,'-vni {0} -peerip {1}'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtraceReqStat(testscript.parameters['uut3'],log,'-vni {0} -peerip {1}'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC045(aetest.Testcase):

      """ Verify OAM Traceroute for remote host IP """

      uid = 'VMCT-MCAST-OAM-FUNC-045'
      @aetest.test
      def vMctMCASTTraceRouteHostIp(self,log,testscript,testbed,vtep_list):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC046(aetest.Testcase):

      """ Verify OAM Traceroute for remote host MAC """

      uid = 'VMCTMCAST-OAM-FUNC-046'
      @aetest.test
      def vMctMCASTTraceRouteHostMac(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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



         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC047(aetest.Testcase):

      """ Verify OAM Ping for remote host MAC """

      uid = 'VMCT-MCAST-OAM-FUNC-047'
      @aetest.test
      def vMctMCASTPingHostMac(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')
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


         oam_lib.configNgoamProfile(testscript.parameters['configdict']['oam_config_dict']['uut1']['profile2'],testscript.parameters['uut1'],log)
         oam_lib.configNgoamProfile(testscript.parameters['configdict']['oam_config_dict']['uut3']['profile2'],testscript.parameters['uut3'],log)
 
         log.info('Verify the Ping for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamPingMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -macvlan {1} -profile {3} -interface {2}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['profile_oamchannel'])):
               log.info('Ping for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -macvlan {1} -profile {3} -interface {2}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['profile_oamchannel'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC048(aetest.Testcase):

      """ Verify OAM Traceroute verbose for remote host MAC """

      uid = 'VMCT-MCAST-OAM-FUNC-048'
      @aetest.test
      def vMctMCASTTraceRouteVerboseHostMac(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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



         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC049(aetest.Testcase):

      """ Verify OAM Ping verbose for remote host MAC """

      uid = 'VMCT-MCAST-OAM-FUNC-049'
      @aetest.test
      def vMctMCASTPingVerboseHostMac(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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



         oam_lib.configNgoamProfile(testscript.parameters['configdict']['oam_config_dict']['uut1']['profile2'],testscript.parameters['uut1'],log)
         oam_lib.configNgoamProfile(testscript.parameters['configdict']['oam_config_dict']['uut3']['profile2'],testscript.parameters['uut3'],log)
 
         log.info('Verify the Ping for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamPingMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -macvlan {1} -interface {2} -profile {3} -verbose True'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['profile_oamchannel'])):
               log.info('Ping for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -macvlan {1} -interface {2} -profile {3} -verbose True'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['profile_oamchannel'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC050(aetest.Testcase):

      """ Verify NGOAM with uplink Flap"""

      uid = 'VMCT-MCAST-OAM-FUNC-050'
      @aetest.test
      def vMctMCASTngoamUplinkFlap(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(30)

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


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Flapping the Uplink')
         result= pcall (vxlan_lib.flapUplink,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping uplink passed')
         else:
                 log.error('Flapping uplink failed')
                 self.failed()

         time.sleep(120)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after uplink flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after uplink flap')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after uplink flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after uplink flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after uplink flap')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after uplink flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after uplink flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after uplink flap')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after uplink flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after uplink flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after uplink flap')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after uplink flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after uplink flap')
         else:
                   log.error('OAM pathtrace is not working as expected after uplink flap')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after uplink flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after uplink flap')
         else:
                   log.error('OAM pathtrace is not working as expected after uplink flap')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after uplink flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after uplink flap')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after uplink flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after uplink flap')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after uplink flap')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after uplink flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after uplink flap')
         else:
                log.error('The Traffic Drop is more then expected after uplink flap')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC051(aetest.Testcase):

      """ Verify NGOAM with Access link Flap"""

      uid = 'VMCT-MCAST-OAM-FUNC-051'
      @aetest.test
      def vMctMCASTngoamAccesslinkFlap(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(120)

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


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Flapping the Access link')
         result= pcall (vxlan_lib.flapAccesslink,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping Access link passed')
         else:
                 log.error('Flapping Access link failed')
                 self.failed()


         time.sleep(120)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after Access flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after Access flap')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after Access flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after Access flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after Access flap')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after Access flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after Access flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after Access flap')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after Access flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after Access flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after Access flap')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after Access flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after Access flap')
         else:
                   log.error('OAM pathtrace is not working as expected after Access flap')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after Access flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after Access flap')
         else:
                   log.error('OAM pathtrace is not working as expected after Access flap')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after Access flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after Access flap')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after Access flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after Access flap')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after Access flap')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after Access flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after Access flap')
         else:
                log.error('The Traffic Drop is more then expected after Access flap')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')
         time.sleep(30) 

class VMCTMCASTOAMFUNC0502(aetest.Testcase):

      """ Verify NGOAM with NVE Flap"""

      uid = 'VMCT-MCAST-OAM-FUNC-052'
      @aetest.test
      def vMctMCASTngoamNveFlap(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
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


         time.sleep(120)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after flap')
         else:
                log.error('The Traffic Drop is more then expected after flap')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC053(aetest.Testcase):

      """ Verify NGOAM with NVE source Flap"""

      uid = 'VMCT-MCAST-OAM-FUNC-053'
      @aetest.test
      def vMctMCASTngoamNveSourceFlap(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(50)

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


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Nve Source Int Flap')
         result= pcall (vxlan_lib.flapNveSourceInt,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])


         time.sleep(150)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after flap')
         else:
                log.error('The Traffic Drop is more then expected after flap')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC054(aetest.Testcase):

      """ Verify NGOAM with Vxlan VRF Flap"""

      uid = 'VMCT-MCAST-OAM-FUNC-054'
      @aetest.test
      def vMctMCASTngoamVxlanVrfFlap(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')


         time.sleep(50)

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


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Flapping the VXLAN VRF')
         result= pcall (vxlan_lib.flapVxlanVrf,log=testscript.parameters['vpc_log_list'],hdl=testscript.parameters['vpc_hdl_list'],dut=testscript.parameters['vpc_dut_list'],configDict=testscript.parameters['vpc_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping of VXLAN VRF passed')
         else:
                 log.error('Flapping of VXLAN VRF failed')
                 self.failed()
 
         time.sleep(120)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after flap')
         else:
                log.error('The Traffic Drop is more then expected after flap')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC055(aetest.Testcase):

      """ Verify NGOAM with L2 VNI SVI Flap"""

      uid = 'VMCT-MCAST-OAM-FUNC-055'
      @aetest.test
      def vMctMCASTngoamVxlanL2VNISviFlap(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Flapping the L2 Vni Svi')
         result= pcall (vxlan_lib.flapL2VniSvi,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping of L2 Vni Svi passed')
         else:
                 log.error('Flapping of L2 Vni Svi failed')
                 self.failed()
 
         time.sleep(150)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after flap')
         else:
                log.error('The Traffic Drop is more then expected after flap')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC056(aetest.Testcase):

      """ Verify NGOAM with L3 VNI SVI Flap"""

      uid = 'VMCT-MCAST-OAM-FUNC-056'
      @aetest.test
      def vMctMCASTngoamVxlanL3VNISviFlap(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Flapping the L3 Vni Svi')
         result= pcall (vxlan_lib.flapL3VniSvi,log=testscript.parameters['log_list'],hdl=testscript.parameters['hdl_list'],dut=testscript.parameters['dut_list'],configDict=testscript.parameters['configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping of L3 Vni Svi passed')
         else:
                 log.error('Flapping of L3 Vni Svi failed')
                 self.failed()
         time.sleep(120)


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after flap')
         else:
                log.error('The Traffic Drop is more then expected after flap')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTOAMFUNC057(aetest.Testcase):

      """ Verify NGOAM with BGP Flap"""

      uid = 'VMCT-MCAST-OAM-FUNC-057'
      @aetest.test
      def vMctMCASTngoamVxlanBGPFlap(self,log,testscript,testbed):

         fail_result=0
         log.info(banner('Configuring OAM profile'))
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
            vtep.configure('ngoam install acl')

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


         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected')
         else:
                   log.error('OAM pathtrace is not working as expected')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Ping to remote host from standalone to VPC is not working')
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


         time.sleep(120)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after flap'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after flap')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after flap')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after flap')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after flap')
         else:
                   log.error('OAM pathtrace is not working as expected after flap')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after flap')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after flap')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after flap')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after flap')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after flap')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after flap')
         else:
                log.error('The Traffic Drop is more then expected after flap')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VMCTMCASTFUNC058(aetest.Testcase):

     """Multiple Flap Uplinks"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-058'

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

class VMCTMCASTFUNC059(aetest.Testcase):

     """Multiple Flap Access links"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-059'

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

class VMCTMCASTFUNC060(aetest.Testcase):

     """Reload vMCT Peer"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-060'

     @aetest.test
     def vmctMCASTreloadPeer(self,log,testscript,testbed):

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

         log.info('Reload vMct Peer')
         testscript.parameters['uut1'].execute('copy r s',timeout=120)
         testscript.parameters['uut1'].reload(prompt_recovery=True, timeout=1200)
         time.sleep(350)
           
       #   if vxlan_lib.verifyfexState(log,testscript.parameters['uut1']):
       #           log.info('Reload was sucessfull')
       #   else:
       #           log.error('Reload failed')
       #           self.failed()               
         time.sleep(90)

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

class VMCTMCASTFUNC061(aetest.Testcase):

     """Reload vMCT Peer Secondary"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-061'

     @aetest.test
     def vmctMCASTreloadSecondaryPeer(self,log,testscript,testbed):

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

         log.info('Reload vMct Secondary Peer')
         testscript.parameters['uut2'].execute('copy r s',timeout=120)
         testscript.parameters['uut2'].reload(prompt_recovery=True, timeout=1200)
         time.sleep(350)
           
       #   if vxlan_lib.verifyfexState(log,testscript.parameters['uut2']):
       #           log.info('Reload was sucessfull')
       #   else:
       #           log.error('Reload failed')
       #           self.failed()               
         time.sleep(90)

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

class VMCTMCASTFUNC062(aetest.Testcase):

     """Reload vMCT Spine"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-062'

     @aetest.test
     def vmctMCASTreloadSpine(self,log,testscript,testbed):

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

         log.info('Reload vMct Spine')
         testscript.parameters['uut4'].execute('copy r s',timeout=120)
         testscript.parameters['uut4'].reload(prompt_recovery=True, timeout=1200)
         time.sleep(350)
           
         time.sleep(90)

         log.info('Verifying traffic after vMCT Spine  reload')

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

class VMCTMCASTFUNC063(aetest.Testcase):

     """Reload vMCT Remote Peer"""

     uid = 'VXLAN-VMCT-MCAST-FUNC-063'

     @aetest.test
     def vmctMCASTreloadRemotePeer(self,log,testscript,testbed):

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

         log.info('Reload vMct Remote Peer')
         testscript.parameters['uut3'].execute('copy r s',timeout=120)
         testscript.parameters['uut3'].reload(prompt_recovery=True, timeout=1200)
         time.sleep(350)
           
         log.info('Verifying traffic after vMCT Remote peer reload')

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


