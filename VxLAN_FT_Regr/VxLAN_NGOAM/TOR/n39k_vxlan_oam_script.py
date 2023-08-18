# Example
# -------
#   OAM
#   

from pyats import aetest
from common_lib import config_bringup
import yaml
import logging
from pyats.topology import loader
import argparse

# pyATS imports

from unicon import Connection
from unicon import Unicon
from ats import aetest
from ats.log.utils import banner
from ats.datastructures.logic import Not, And, Or
from ats.easypy import run
from ats.log.utils import banner
from common_lib import bringup_lib
from feature_lib.vxlan import evpn_lib
from feature_lib.vxlan import vxlan_lib
from feature_lib.vxlan import oam_lib
from pyats.async_ import pcall
from pyats.async_ import Pcall
import time
from common_lib import tgnConfig_lib
#import tgnConfig_lib_test
from common_lib import tgn_lib
from common_lib import config_lib
from common_lib import config_bringup_test
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
        fail_result=0
        testscript.parameters['fail_result']=fail_result 
        log.info('Getting testbed objects from the testbed file')
        testbed_obj = testbed
        log.info(banner('Executing the Infra bring up'))
      #   setup_obj = config_bringup_test.configSetup(configdict,testbed_obj,log)
        configdict=config_bringup_test.convertConfig(configdict,testbed_obj)
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

        # declaring vtep list
        vtep_list=[]
        vtep_list=[uut1,uut2,uut3]
        testscript.parameters['vtep_list']=vtep_list
        vpc_list=[]
        vpc_list=[uut1,uut2]
        testscript.parameters['vpc_list']=vpc_list
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
        vpc_peer='20.20.20.21'
        testscript.parameters['vpc_peer']=vpc_peer
        stand_peer='20.20.20.20'
        testscript.parameters['stand_peer']=stand_peer
        vpchost_mac='2222.2201.0101'
        testscript.parameters['vpchost_mac']=vpchost_mac
        vpchost_vlan=2
        testscript.parameters['vpchost_vlan']=vpchost_vlan
        standhost_mac='0010.9411.0101'
        testscript.parameters['standhost_mac']=standhost_mac
        standhost_vlan=52
        testscript.parameters['standhost_vlan']=standhost_vlan
        '''
        # TGEN Connection 
        tgen=testbed.devices['TG1']
        testscript.parameters['tgen']=tgen
        log.info('TGEN connect')
        tgen.connect()
        time.sleep(90)
                
        log.info('Configuring TGEN device profile')

        result,device_hdl_dict,device_hdl_perVlanDict=tgnConfig_lib.configureDevicesPerVlan(log,tgen,configdict['traffic_config_dict'])

        if result:
                 log.info('Traffic device Config Passed')
                 testscript.parameters['device_hdl_dict']=device_hdl_dict
                 testscript.parameters['device_hdl_perVlanDict']=device_hdl_perVlanDict
        else:
                 log.error('Traffic device Config failed')
                 self.failed() 
        time.sleep(60)
        log.info('configuring Traffic profile in TGEN')
        traffic_result,traffic_handle_dict=tgnConfig_lib.configV4PortBoundTraffic(log,tgen,configdict['traffic_config_dict']['traffic_config']['host_bound'],device_hdl_dict)

        if not traffic_result:
               log.error('Traffic config failed')
               self.failed()
        testscript.parameters['traffic_handle_dict']=traffic_handle_dict

        if re.search('spirent',tgen.type,re.I):
            tgen.stc_apply()
            time.sleep(30)

            tgnConfig_lib.tgn_arp(log,tgen,configdict['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict)
            time.sleep(40)
            tgen.stc_apply()
            time.sleep(30)
        log.info('Starting the traffic')
        result=tgnConfig_lib.tgn_traffic(log,tgen,configdict['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict,'start')
        time.sleep(30)
        result=tgnConfig_lib.tgn_traffic(log,tgen,configdict['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict,'stop')
        time.sleep(20)
        result=tgnConfig_lib.tgn_traffic(log,tgen,configdict['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict,'start')
        time.sleep(30)
        log.info('Verifying traffic ')
        if tgnConfig_lib.verifyTrafficDrop(log,tgen,configdict['traffic_config_dict']['traffic_config']['host_bound'],traffic_handle_dict):
                log.info('The traffic drop is not seen')
        else:
                log.error('The Traffic Drop is more then expected')
                self.failed()
        '''

class setupConfigVxlan(aetest.Testcase):

    """ Configure VXLAN """
 
    uid = 'setupConfigVxlan'
    @aetest.test
    def ConfigVxlan(self,log,testscript,testbed):
        log.info(banner('Configuring VXLAN related configs on all VTEPS'))
        setup_result= pcall (vxlan_lib.setupConfigVxlanScale,hdl=testscript.parameters['vtep_list'],dut=testscript.parameters['dut_list'],log=testscript.parameters['log_list'],config_dict=testscript.parameters['configdict_list'])
        if testscript.parameters['fail_result'] not in setup_result:
                 log.info('Vxlan config passed')
        else:
                 log.error('Vxlan config failed')
                 self.failed()

class setupTgen(aetest.Testcase):
      """Configure TGEN"""

      uid = 'setupTgen'
      @aetest.test
      def SetUpTgen(self,log,testscript,testbed):   
 
        #TGEN Connection 
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

        if re.search('spirent',tgen.type,re.I):
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

 
class VXLANOAMFUNC001(aetest.Testcase):

    """ Enable / disable of NGOAM feature """
 
    uid = 'VXLAN-OAM-FUNC-001'

    @aetest.test
    def enableDisableNgoam(self,log,testscript,testbed,vtep_list):
        for vtep in vtep_list:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
        for vtep in vtep_list:
            log.info(banner('Disabling feature NGOAM on %s' % vtep))
            out=bringup_lib.unconfigFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Disable of NGOAM passes on VTEP %s' % vtep)
        for vtep in vtep_list:
            log.info(banner('Enabling feature NGOAM on %s' % vtep))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)

class VXLANOAMFUNC002(aetest.Testcase):

      """ Verify OAM profiles can be configured with various options """

      uid = 'VXLAN-OAM-FUNC-002'
      @aetest.test
      def configOAMProfile(self,log,testscript,testbed):
 
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
 
         setup_result = pcall (oam_lib.setupConfigNgoamProfile,hdl=testscript.parameters['vtep_list'],dut=testscript.parameters['dut_list'],log=testscript.parameters['log_list'],config_dict=testscript.parameters['configdict_list'])
         if fail_result not in setup_result:
                 log.info('OAM profile config passed')
         else:
                 log.error('OAM profile config failed')
                 self.failed()

class VXLANOAMFUNC004(aetest.Testcase):

      """ Verify OAM feature and profiles specific configs are NVGENED """

      uid = 'VXLAN-OAM-FUNC-004'
      @aetest.test
      def configOAMProfileFlow(self,log,testscript,testbed):
 
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
 
         setup_result = pcall (oam_lib.setupConfigNgoamProfile,hdl=testscript.parameters['vtep_list'],dut=testscript.parameters['dut_list'],log=testscript.parameters['log_list'],config_dict=testscript.parameters['configdict_list'])
         if fail_result not in setup_result:
                 log.info('OAM profile config passed')
         else:
                 log.error('OAM profile config failed')
                 self.failed()

         log.info(banner('Verifying whether NGOAM clis are NVGENED'))
         ngven_result = oam_lib.verifyOAMNGVEN(testscript.parameters['vtep_list'],log)
         if ngven_result:
                log.info('OAM clis are NGVENED')
         else:
                log.error('OAM clis are not NGVENED as Expected')

class VXLANOAMFUNC005(aetest.Testcase):

      """ Verify OAM feature and profiles specific configs are NVGENED """

      uid = 'VXLAN-OAM-FUNC-005'
      @aetest.test
      def configOAMInstallAcl(self,log,testscript,testbed):
 
         fail_result=0
         for vtep in testscript.parameters['vtep_list']:
            log.info(banner(f'Enabling feature NGOAM on {vtep}'))
            out=bringup_lib.configFeature( vtep, log, '-feature ngoam' )
            if out.result=='fail':
                log.error('Enable disable of NGOAM failed on VTEP %s' % vtep)
                self.failed()
            else:
                log.info('Enable disable of NGOAM passes on VTEP %s' % vtep)
 
         log.info(banner('Configuring OAM profile'))
         setup_result = pcall (oam_lib.setupConfigNgoamProfile,hdl=testscript.parameters['vtep_list'],dut=testscript.parameters['dut_list'],log=testscript.parameters['log_list'],config_dict=testscript.parameters['configdict_list'])
         if fail_result not in setup_result:
                 log.info('OAM profile config passed')
         else:
                 log.error('OAM profile config failed')
                 self.failed()
         for vtep in testscript.parameters['vtep_list']:
              log.info('Configuring NGOAM ACL')
              if oam_lib.configAndVerifyNgoamAcl(vtep, log):
                     log.info('OAM ACL installed as expected')
              else:
                     log.error('OAM ACL not installed as expected')
                     self.failed()
         log.info(banner('Verifying whether NGOAM clis are NVGENED'))
         ngven_result = oam_lib.verifyOAMNGVEN(testscript.parameters['vtep_list'],log)
         if ngven_result:
                log.info('OAM clis are NGVENED')
         else:
                log.error('OAM clis are not NGVENED as Expected')

class VXLANOAMFUNC006(aetest.Testcase):

      """ Verify OAM Ping using vni option """

      uid = 'VXLAN-OAM-FUNC-006'
      @aetest.test
      def pingOamHostIpVni(self,log,testscript,testbed,vtep_list):

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
         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')


class VXLANOAMFUNC007(aetest.Testcase):

      """ Verify OAM Ping using different interface  """

      uid = 'VXLAN-OAM-FUNC-007'
      @aetest.test
      def pingOamHostIpVniEgress(self,log,testscript,testbed):

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



class VXLANOAMFUNC008(aetest.Testcase):

      """ Verify OAM Ping using vrf option """

      uid = 'VXLAN-OAM-FUNC-008'
      @aetest.test
      def pingOamHostIpVrf(self,log,testscript,testbed,vtep_list):

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


class VXLANOAMFUNC009(aetest.Testcase):

      """ Verify OAM Ping using Sport """

      uid = 'VXLAN-OAM-FUNC-009'
      @aetest.test
      def pingOamHostIpVniSport(self,log,testscript,testbed,vtep_list):

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


class VXLANOAMFUNC010(aetest.Testcase):

      """ Verify OAM Ping using different interface via VRF option  """

      uid = 'VXLAN-OAM-FUNC-010'
      @aetest.test
      def pingOamHostIpVrfEgress(self,log,testscript,testbed):

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


class VXLANOAMFUNC011(aetest.Testcase):

      """ Verify OAM Ping using Sport via vrf option"""

      uid = 'VXLAN-OAM-FUNC-011'
      @aetest.test
      def pingOamHostIpVrfSport(self,log,testscript,testbed):
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



class VXLANOAMFUNC012(aetest.Testcase):

      """ Verify OAM Ping using profile """

      uid = 'VXLAN-OAM-FUNC-012'
      @aetest.test
      def pingOamHostIPProfile(self,log,testscript,testbed,vtep_list):

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

class VXLANOAMFUNC013(aetest.Testcase):

      """ Verify OAM Ping using vni option with traffic Flow"""

      uid = 'VXLAN-OAM-FUNC-013'
      @aetest.test
      def pingOamHostIpVniTraffic(self,log,testscript,testbed,vtep_list):

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
 

class VXLANOAMFUNC014(aetest.Testcase):

      """ Verify OAM Pathtrace to NVE  """

      uid = 'VXLAN-OAM-FUNC-014'
      @aetest.test
      def PathtraceNve (self,log,testscript,testbed):

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


class VXLANOAMFUNC015(aetest.Testcase):

      """ Verify OAM Pathtrace to NVE with traffic"""

      uid = 'VXLAN-OAM-FUNC-015'
      @aetest.test
      def PathtraceNveTraffic (self,log,testscript,testbed):

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
         time.sleep(30) 
 


class VXLANOAMFUNC016(aetest.Testcase):

      """ Verify OAM Pathtrace to NVE with Verbose  """

      uid = 'VXLAN-OAM-FUNC-016'
      @aetest.test
      def PathtraceNve (self,log,testscript,testbed):

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


class VXLANOAMFUNC017(aetest.Testcase):

      """ Verify OAM Pathtrace with Req-stat to NVE  """

      uid = 'VXLAN-OAM-FUNC-017'
      @aetest.test
      def PathtraceNveReqStat (self,log,testscript,testbed):

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



class VXLANOAMFUNC018(aetest.Testcase):

      """ Verify OAM Traceroute for remote host IP """

      uid = 'VXLAN-OAM-FUNC-018'
      @aetest.test
      def TraceRouteHostIp(self,log,testscript,testbed,vtep_list):

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


class VXLANOAMFUNC019(aetest.Testcase):

      """ Verify OAM Traceroute for remote host MAC """

      uid = 'VXLAN-OAM-FUNC-019'
      @aetest.test
      def TraceRouteHostMac(self,log,testscript,testbed):

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


class VXLANOAMFUNC020(aetest.Testcase):

      """ Verify OAM Ping for remote host MAC """

      uid = 'VXLAN-OAM-FUNC-020'
      @aetest.test
      def PingHostMac(self,log,testscript,testbed):

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


class VXLANOAMFUNC021(aetest.Testcase):

      """ Verify OAM Traceroute verbose for remote host MAC """

      uid = 'VXLAN-OAM-FUNC-021'
      @aetest.test
      def TraceRouteVerboseHostMac(self,log,testscript,testbed):

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


class VXLANOAMFUNC022(aetest.Testcase):

      """ Verify OAM Ping verbose for remote host MAC """

      uid = 'VXLAN-OAM-FUNC-022'
      @aetest.test
      def PingVerboseHostMac(self,log,testscript,testbed):

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


class VXLANOAMFUNC023(aetest.Testcase):

      """ Verify OAM Traceroute for remote host IP with Traffic """

      uid = 'VXLAN-OAM-FUNC-023'
      @aetest.test
      def TraceRouteHostIp(self,log,testscript,testbed,vtep_list):

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

         log.info('Verifying traffic after NGOAM Traceroute ')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')
         time.sleep(30) 

class VXLANOAMFUNC024(aetest.Testcase):

      """ Verify OAM Ping verbose for remote host MAC with traffic """

      uid = 'VXLAN-OAM-FUNC-024'
      @aetest.test
      def PingVerboseHostMacTraffic(self,log,testscript,testbed):

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
         oam_lib.configNgoamProfile(testscript.parameters['configdict']['oam_config_dict']['uut1']['profile2'],testscript.parameters['uut1'],log)
         oam_lib.configNgoamProfile(testscript.parameters['configdict']['oam_config_dict']['uut3']['profile2'],testscript.parameters['uut3'],log)
 
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

         log.info('Verifying traffic after NGOAM Ping Mac')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VXLANOAMFUNC025(aetest.Testcase):

      """ Verify OAM Traceroute verbose for remote host MAC with traffic """

      uid = 'VXLAN-OAM-FUNC-025'
      @aetest.test
      def TraceRouteVerboseHostMac(self,log,testscript,testbed):

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

         log.info('Verify the Traceroute from standalone VTEP to VPC')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working')
               self.failed()

         log.info('Verifying traffic after NGOAM Traceroute Mac ')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen')
         else:
                log.error('The Traffic Drop is more then expected')
                self.failed()

         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')
         time.sleep(30) 

class VXLANOAMFUNC026(aetest.Testcase):

      """ Verify NGOAM with uplink Flap"""

      uid = 'VXLAN-OAM-FUNC-026'
      @aetest.test
      def ngoamUplinkFlap(self,log,testscript,testbed):

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

class VXLANOAMFUNC027(aetest.Testcase):

      """ Verify NGOAM with Access link Flap"""

      uid = 'VXLAN-OAM-FUNC-027'
      @aetest.test
      def ngoamAccesslinkFlap(self,log,testscript,testbed):

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

class VXLANOAMFUNC028(aetest.Testcase):

      """ Verify NGOAM with NVE Flap"""

      uid = 'VXLAN-OAM-FUNC-028'
      @aetest.test
      def ngoamNveFlap(self,log,testscript,testbed):

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


class VXLANOAMFUNC029(aetest.Testcase):

      """ Verify NGOAM with NVE source Flap"""

      uid = 'VXLAN-OAM-FUNC-029'
      @aetest.test
      def ngoamNveSourceFlap(self,log,testscript,testbed):

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


class VXLANOAMFUNC030(aetest.Testcase):

      """ Verify NGOAM with Vxlan VRF Flap"""

      uid = 'VXLAN-OAM-FUNC-030'
      @aetest.test
      def ngoamVxlanVrfFlap(self,log,testscript,testbed):

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


class VXLANOAMFUNC031(aetest.Testcase):

      """ Verify NGOAM with L2 VNI SVI Flap"""

      uid = 'VXLAN-OAM-FUNC-031'
      @aetest.test
      def ngoamVxlanL2VNISviFlap(self,log,testscript,testbed):

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

class VXLANOAMFUNC032(aetest.Testcase):

      """ Verify NGOAM with L3 VNI SVI Flap"""

      uid = 'VXLAN-OAM-FUNC-032'
      @aetest.test
      def ngoamVxlanL3VNISviFlap(self,log,testscript,testbed):

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

class VXLANOAMFUNC033(aetest.Testcase):

      """ Verify NGOAM with BGP Flap"""

      uid = 'VXLAN-OAM-FUNC-033'
      @aetest.test
      def ngoamVxlanBGPFlap(self,log,testscript,testbed):

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

class VXLANOAMFUNC034(aetest.Testcase):

      """ Verify NGOAM with BGP EVPN Neighbor Flap"""

      uid = 'VXLAN-OAM-FUNC-034'
      @aetest.test
      def ngoamVxlanBGPNeighborFlap(self,log,testscript,testbed):

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


class VXLANOAMFUNC035(aetest.Testcase):

      """ Verify NGOAM with clear BGP"""

      uid = 'VXLAN-OAM-FUNC-035'
      @aetest.test
      def ngoamVxlanBGPClear(self,log,testscript,testbed):

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

         log.info('clear BGP routes')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear ip bgp *')
         time.sleep(120)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after clear ')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after clear'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after clear')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after clear'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after clear')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after clear')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after clear')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after clear')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after clear')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after clear')
         else:
                   log.error('OAM pathtrace is not working as expected after clear')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after clear')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after clear')
         else:
                   log.error('OAM pathtrace is not working as expected after clear')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after clear')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after clear')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after clear')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after clear')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after clear')
         else:
                log.error('The Traffic Drop is more then expected after clear')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VXLANOAMFUNC036(aetest.Testcase):

      """ Verify NGOAM with clear ip route"""

      uid = 'VXLAN-OAM-FUNC-036'
      @aetest.test
      def ngoamVxlanRouteClear(self,log,testscript,testbed):

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

         log.info('clear ip routes')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear ip route *')
 
         time.sleep(120)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after clear ')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after clear'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after clear')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after clear'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after clear')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after clear')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after clear')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after clear')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after clear')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after clear')
         else:
                   log.error('OAM pathtrace is not working as expected after clear')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after clear')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after clear')
         else:
                   log.error('OAM pathtrace is not working as expected after clear')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after clear')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after clear')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after clear')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after clear')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after clear')
         else:
                log.error('The Traffic Drop is more then expected after clear')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VXLANOAMFUNC037(aetest.Testcase):

      """ Verify NGOAM with clear ip arp"""

      uid = 'VXLAN-OAM-FUNC-037'
      @aetest.test
      def ngoamVxlanArpClear(self,log,testscript,testbed):

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

         log.info('clear ip arp')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear ip arp')
 
         time.sleep(120)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after clear ')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after clear'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after clear')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after clear'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after clear')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after clear')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after clear')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after clear')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after clear')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after clear')
         else:
                   log.error('OAM pathtrace is not working as expected after clear')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after clear')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after clear')
         else:
                   log.error('OAM pathtrace is not working as expected after clear')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after clear')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after clear')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after clear')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after clear')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after clear')
         else:
                log.error('The Traffic Drop is more then expected after clear')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VXLANOAMFUNC038(aetest.Testcase):

      """ Verify NGOAM with clear mac"""

      uid = 'VXLAN-OAM-FUNC-038'
      @aetest.test
      def ngoamVxlanArpClear(self,log,testscript,testbed):

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

         log.info('clear mac Address Table')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.execute('clear mac address-table dynamic ')
 
         time.sleep(160)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after clear ')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after clear'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after clear')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after clear'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after clear')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after clear')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after clear')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after clear')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after clear')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after clear')
         else:
                   log.error('OAM pathtrace is not working as expected after clear')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after clear')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after clear')
         else:
                   log.error('OAM pathtrace is not working as expected after clear')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after clear')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after clear')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after clear')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after clear')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after clear')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after clear')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after clear')
         else:
                log.error('The Traffic Drop is more then expected after clear')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')

class VXLANOAMFUNC039(aetest.Testcase):

      """ Verify NGOAM with reload"""

      uid = 'VXLAN-OAM-FUNC-039'
      @aetest.test
      def ngoamVxlanReload(self,log,testscript,testbed):

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

         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)

         log.info('Verify the Traceroute for Dst MAC from VPC to standalone VTEP after reload')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut1'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['standhost_mac'],testscript.parameters['standhost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut1']['eth'],testscript.parameters['vpc_peer'])):
               log.info('Traceroute for Dst MAC from VPC {0} to standalone {1} is working as expected after reload'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after reload')
               self.failed()

         log.info('Verify the Traceroute from VPC to standalone VTEP after reload')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vrf'],testscript.parameters['source_vpc'])):
         
               log.info('Traceroute to remote host from VPC {0} to standalone {1} is working as expected after reload'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Traceroute to remote host from VPC to standalone  is not working after reload')
               self.failed()

         log.info('Verify the Traceroute from standalone VTEP to VPC after reload')
         if oam_lib.OamTraceRouteIPAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vrf {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vrf'],testscript.parameters['source_stand'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after reload')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after reload')
               self.failed()


         log.info('Verify the Traceroute from standalone VTEP to VPC after reload')
         if oam_lib.OamTraceRouteMacAndVerify(testscript.parameters['uut3'],log,'-hostmac {0} -hostvlan {1} -interface {2} -verbose True -nvepeer {3}'.format(testscript.parameters['vpchost_mac'],testscript.parameters['vpchost_vlan'],testscript.parameters['configdict']['vxlan_uplink_dict']['uut3']['PO'],testscript.parameters['stand_peer'])):
               log.info('Traceroute to remote host from standalone to VPC  is working as expected after reload')
         else:
               log.error('Traceroute to remote host from standalone to VPC is not working after reload')
               self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in VPC after reload')
         if oam_lib.verifyPathtrace(testscript.parameters['uut1'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['vpc_peer'])):

                   log.info('OAM pathtrace is working as expected after reload')
         else:
                   log.error('OAM pathtrace is not working as expected after reload')
                   self.failed()

         log.info(f'Verify Pathtrace for all NVE peer in Standalone after reload')
         if oam_lib.verifyPathtrace(testscript.parameters['uut3'],log,'-vni {0} -peerip {1} -verbose True'.format(testscript.parameters['vni'],testscript.parameters['stand_peer'])):
                   log.info('OAM pathtrace is working as expected after reload')
         else:
                   log.error('OAM pathtrace is not working as expected after reload')
                   self.failed()

         log.info('Verify the Ping from VPC to standalone VTEP after reload')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut1'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['stand_host'],testscript.parameters['vni'],testscript.parameters['source_vpc'])):
         
               log.info('Ping to remote host from VPC {0} to standalone {1} is working as expected'.format(testscript.parameters['uut1'],testscript.parameters['uut3']))
         else:
               log.error('Ping to remote host from VPC to standalone  is not working after reload')
               self.failed()

         log.info('Verify the Ping from standalone VTEP to VPC after reload')
         if oam_lib.OamPingAndVerify(testscript.parameters['uut3'],log,'-hostip {0} -vni {1} -source {2}'.format(testscript.parameters['vpc_host'],testscript.parameters['vni'],testscript.parameters['source_stand'])):
               log.info('Ping to remote host from standalone to VPC  is working as expected after reload')
         else:
               log.error('Ping to remote host from standalone to VPC is not working after reload')
               self.failed()


         log.info('Verifying traffic after NGOAM Traceroute Mac after reload')
         if tgnConfig_lib.verifyTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict']):
                log.info('The traffic drop is not seen after reload')
         else:
                log.error('The Traffic Drop is more then expected after reload')
                self.failed()

         log.info('Verifying BUM Traffic')

         if tgnConfig_lib.verifyBUMTraffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict']):
                log.info('The BUM Traffic working as expected')
         else:
                log.error('The BUM traffic is not working as expected')
                self.failed()


         log.info('Stopping the traffic')

         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['host_bound'],testscript.parameters['traffic_handle_dict'],'stop')


class VXLANOAMFUNC040(aetest.Testcase):

      """ Verify NGOAM with Access link Flap after reload"""

      uid = 'VXLAN-OAM-FUNC-040'
      @aetest.test
      def ngoamAccesslinkFlapAfterReload(self,log,testscript,testbed):

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

         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)


         log.info('Flapping the Access link after reload')
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

class VXLANOAMFUNC041(aetest.Testcase):

      """ Verify NGOAM with NVE Flap after reload"""

      uid = 'VXLAN-OAM-FUNC-041'
      @aetest.test
      def ngoamNveFlapAfterReload(self,log,testscript,testbed):

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


         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)

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


class VXLANOAMFUNC042(aetest.Testcase):

      """ Verify NGOAM with NVE source Flap after reload"""

      uid = 'VXLAN-OAM-FUNC-042'
      @aetest.test
      def ngoamNveSourceFlapReload(self,log,testscript,testbed):

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

         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)


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


class VXLANOAMFUNC043(aetest.Testcase):

      """ Verify NGOAM with Vxlan VRF Flapi after reload"""

      uid = 'VXLAN-OAM-FUNC-043'
      @aetest.test
      def ngoamVxlanVrfFlapReload(self,log,testscript,testbed):

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

         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)

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


class VXLANOAMFUNC044(aetest.Testcase):

      """ Verify NGOAM with L2 VNI SVI Flap after reload"""

      uid = 'VXLAN-OAM-FUNC-044'
      @aetest.test
      def ngoamVxlanReloadL2VNISviFlap(self,log,testscript,testbed):

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

         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)


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

class VXLANOAMFUNC045(aetest.Testcase):

      """ Verify NGOAM with L3 VNI SVI Flap After reload"""

      uid = 'VXLAN-OAM-FUNC-045'
      @aetest.test
      def ngoamVxlanReloadL3VNISviFlap(self,log,testscript,testbed):

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

         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)


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

class VXLANOAMFUNC046(aetest.Testcase):

      """ Verify NGOAM with BGP Flap After reload"""

      uid = 'VXLAN-OAM-FUNC-046'
      @aetest.test
      def ngoamVxlanReloadBGPFlap(self,log,testscript,testbed):

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

         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)


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

class VXLANOAMFUNC047(aetest.Testcase):

      """ Verify Relaod NGOAM with uplink Flap"""

      uid = 'VXLAN-OAM-FUNC-047'
      @aetest.test
      def ngoamReloadUplinkFlap(self,log,testscript,testbed):

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

         log.info('Reload all the VTEP')
         for vtep in testscript.parameters['vtep_list']:
                 vtep.reload(prompt_recovery=True, timeout=1200)
 
         time.sleep(350)


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

