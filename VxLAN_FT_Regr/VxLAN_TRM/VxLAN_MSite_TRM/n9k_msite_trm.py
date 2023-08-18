# Example
# -------
#   Msite TRM
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
        uut7 = testbed.devices['uut7']
        testscript.parameters['uut7'] = uut7
        uut8 = testbed.devices['uut2']
        testscript.parameters['uut8'] = uut8
        uut9 = testbed.devices['uut9']
        testscript.parameters['uut9'] = uut9
        uut10 = testbed.devices['uut10']
        testscript.parameters['uut10'] = uut10
        uut11 = testbed.devices['uut11']
        testscript.parameters['uut11'] = uut11
        uut12 = testbed.devices['uut12']
        testscript.parameters['uut12'] = uut12
        uut13 = testbed.devices['uut13']
        testscript.parameters['uut13'] = uut13
        uut14 = testbed.devices['uut14']
        testscript.parameters['uut14'] = uut14
        uut15 = testbed.devices['uut15']
        testscript.parameters['uut15'] = uut15
        uut16 = testbed.devices['uut16']
        testscript.parameters['uut16'] = uut16


        # declaring vtep list
        vtep_list=[]
        vtep_list=[uut1,uut2,uut3,uut4,uut5,uut9,uut10,uut11]
        testscript.parameters['vtep_list']=vtep_list
        vpc_list=[]
        vpc_list=[uut1,uut2]
        testscript.parameters['vpc_list']=vpc_list
        #ngoamAcl_pattern='DATA=0x00008902'
        #testscript.parameters['ngoamAcl_pattern']=ngoamAcl_pattern        
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

        #BGW
        bgw_list=[]        
        bgw_list=[uut1,uut2,uut3,uut4,uut5]
        testscript.parameters['bgw_list']=bgw_list
        bgw_hdl_list=[]
        bgw_configdict_list=[]
        bgw_dut_list=[]
        bgw_log_list=[]
        for bgw in bgw_list:
                bgw_hdl_list.append(bgw)
                bgw_dut_list.append(bgw.alias)
                bgw_configdict_list.append(configdict)
                bgw_log_list.append(log)
        testscript.parameters['bgw_hdl_list']=bgw_hdl_list
        testscript.parameters['bgw_dut_list']=bgw_dut_list
        testscript.parameters['bgw_configdict_list']=bgw_configdict_list
        testscript.parameters['bgw_log_list']=bgw_log_list


        #LEAF
        leaf_list=[]        
        leaf_list=[uut9,uut10,uut11]
        testscript.parameters['leaf_list']=leaf_list
        leaf_hdl_list=[]
        leaf_configdict_list=[]
        leaf_dut_list=[]
        leaf_log_list=[]
        for leaf in leaf_list:
                leaf_hdl_list.append(leaf)
                leaf_dut_list.append(leaf.alias)
                leaf_configdict_list.append(configdict)
                leaf_log_list.append(log)

        testscript.parameters['leaf_hdl_list']=leaf_hdl_list
        testscript.parameters['leaf_dut_list']=leaf_dut_list
        testscript.parameters['leaf_configdict_list']=leaf_configdict_list
        testscript.parameters['leaf_log_list']=leaf_log_list


        #vpc_hdl_list=[]
        #vpc_configdict_list=[]
        #vpc_dut_list=[]
        #vpc_log_list=[]
        #for vtep in vpc_list:
        #        vpc_hdl_list.append(vtep)
        #        vpc_dut_list.append(vtep.alias)
        #        vpc_configdict_list.append(configdict)
        #        vpc_log_list.append(log)

        #testscript.parameters['vpc_hdl_list']=vpc_hdl_list
        #testscript.parameters['vpc_dut_list']=vpc_dut_list
        #testscript.parameters['vpc_configdict_list']=vpc_configdict_list
        #testscript.parameters['vpc_log_list']=vpc_log_list

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

class setupTgen(aetest.Testcase):

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
        result,igmp_hdl_dict=tgnConfig_lib.configIgmp(log,tgen,testscript.parameters['configdict']['traffic_config_dict'],device_hdl_dict)
        if result:
                 log.info('IGMP Emulation Config Passed')
                 testscript.parameters['igmp_hdl_dict']=igmp_hdl_dict
        else:
                 log.error('IGMP Emulation Config failed')
                 self.failed() 
        time.sleep(60)

        log.info('Start all the Protocols')
        proto_result=tgnConfig_lib.tgn_protocol(log,tgen,'start')
       
        log.info('configuring Mcast Traffic profile in TGEN')
        mcast_traffic_result,mcast_traffic_handle_dict=tgnConfig_lib.configV4McastBoundTraffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],device_hdl_dict,igmp_hdl_dict)

        if not mcast_traffic_result:
               log.error('Traffic config failed')
               self.failed()
        testscript.parameters['mcast_traffic_handle_dict']=mcast_traffic_handle_dict

        log.info('Starting the traffic')
        result=tgnConfig_lib.tgn_traffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],mcast_traffic_handle_dict,'start')

        time.sleep(30)
 
        log.info('Stopping the traffic')
        result=tgnConfig_lib.tgn_traffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

     
        log.info('configuring BUM Traffic profile in TGEN')
        traffic_bum_result,bum_handle_dict=tgnConfig_lib.configBUMTraffic(log,tgen,testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'])

        if not traffic_bum_result:
               log.error('BUM Traffic config failed')
               self.failed()
        testscript.parameters['bum_handle_dict']=bum_handle_dict



class MSITETRM001(aetest.Testcase):

       """MSITE TRM Source is Site1 and Receiver in Site2"""
       uid = 'MSITE-TRM-FUNC-001'

       @aetest.test
       def msiteTrmSourceSite1ToRecieverSite2(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM002(aetest.Testcase):

       """MSITE TRM Source is Site1 and Receiver in Site3"""
       uid = 'MSITE-TRM-FUNC-002'

       @aetest.test
       def msiteTrmSourceSite1ToRecieverSite3(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


class MSITETRM003(aetest.Testcase):

       """MSITE TRM Source is Site2 and Receiver in Site1"""
       uid = 'MSITE-TRM-FUNC-003'

       @aetest.test
       def msiteTrmSourceSite2ToRecieverSite1(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM004(aetest.Testcase):

       """MSITE TRM Source is Site2 and Receiver in Site3"""
       uid = 'MSITE-TRM-FUNC-004'

       @aetest.test
       def msiteTrmSourceSite2ToRecieverSite3(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM005(aetest.Testcase):

       """MSITE TRM Source is Site3 and Receiver in Site1"""
       uid = 'MSITE-TRM-FUNC-005'

       @aetest.test
       def msiteTrmSourceSite3ToRecieverSite1(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM006(aetest.Testcase):

       """MSITE TRM Source is Site3 and Receiver in Site2"""
       uid = 'MSITE-TRM-FUNC-006'

       @aetest.test
       def msiteTrmSourceSite3ToRecieverSite2(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM007(aetest.Testcase):

       """MSITE TRM External Source to Receiver in Site1"""
       uid = 'MSITE-TRM-FUNC-007'

       @aetest.test
       def msiteTrmExtSourceToRecieverSite1(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM008(aetest.Testcase):

       """MSITE TRM External Source to Receiver in Site2"""
       uid = 'MSITE-TRM-FUNC-008'

       @aetest.test
       def msiteTrmExtSourceToRecieverSite2(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM009(aetest.Testcase):

       """MSITE TRM External Source to Receiver in Site3"""
       uid = 'MSITE-TRM-FUNC-009'

       @aetest.test
       def msiteTrmExtSourceToRecieverSite3(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


class MSITETRM010(aetest.Testcase):

       """MSITE TRM BGW L2 vni Add/Delete"""
       uid = 'MSITE-TRM-FUNC-010'

       @aetest.test
       def msiteTrmBGWL2VniDeleteAdd(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Deleting and Adding the L2 VNI configured in BGW')

         result= pcall (vxlan_lib.DeleteAddVxlanL2Vni,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Vxlan Delete and Add L2 VNI passed')
         else:
                 log.error('Vxlan Delete and Add L2 VNI failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM011(aetest.Testcase):

       """MSITE TRM LEAF L2 vni Add/Delete"""
       uid = 'MSITE-TRM-FUNC-011'

       @aetest.test
       def msiteTrmLeafL2VniDeleteAdd(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Deleting and Adding the L2 VNI configured in Leaf')

         result= pcall (vxlan_lib.DeleteAddVxlanL2Vni,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Vxlan Delete and Add L2 VNI passed')
         else:
                 log.error('Vxlan Delete and Add L2 VNI failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM012(aetest.Testcase):

       """MSITE TRM BGW L3 vni Add/Delete"""
       uid = 'MSITE-TRM-FUNC-012'

       @aetest.test
       def msiteTrmBgwL3VniDeleteAdd(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         result= pcall (vxlan_lib.DeleteAddVxlanL3Vni,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Vxlan Delete and Add L3 VNI  passed')
         else:
                 log.error('Vxlan Delete and Add L3 VNI failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


class MSITETRM013(aetest.Testcase):

       """MSITE TRM Leaf L3 vni Add/Delete"""
       uid = 'MSITE-TRM-FUNC-013'

       @aetest.test
       def msiteTrmLeafL3VniDeleteAdd(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         result= pcall (vxlan_lib.DeleteAddVxlanL3Vni,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Vxlan Delete and Add L3 VNI  passed')
         else:
                 log.error('Vxlan Delete and Add L3 VNI failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM014(aetest.Testcase):

       """MSITE TRM BGW Delete and Add loopback int of NVE"""
       uid = 'MSITE-TRM-FUNC-014'

       @aetest.test
       def msiteTrmBgwAddDeleteLoopback(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         result= pcall (vxlan_lib.AddDeleteNveLoopback,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('NVE loopback remove and add passed')
         else:
                 log.error('NVE loopback remove and add failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM015(aetest.Testcase):

       """MSITE TRM Leaf Delete and Add loopback int of NVE"""
       uid = 'MSITE-TRM-FUNC-015'

       @aetest.test
       def msiteTrmLeafAddDeleteLoopback(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         result= pcall (vxlan_lib.AddDeleteNveLoopback,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('NVE loopback remove and add passed')
         else:
                 log.error('NVE loopback remove and add failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM016(aetest.Testcase):

       """MSITE TRM BGW Flap BGP"""
       uid = 'MSITE-TRM-FUNC-016'

       @aetest.test
       def msiteTrmBgwFlapBgp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the BGP in all BGW')
         for bgw in testscript.parameters['bgw_list']:
                cfg=''
                for as_no in testscript.parameters['configdict']['bgp_config_dict'][bgw.alias]:
                      cfg+='''router bgp {0}
                              shut
                              no shut
                           '''.format(as_no)
                bgw.configure(cfg)


         time.sleep(350)

         log.info('Verifying traffic after flapping BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM017(aetest.Testcase):

       """MSITE TRM Leaf Flap BGP"""
       uid = 'MSITE-TRM-FUNC-017'

       @aetest.test
       def msiteTrmLeafFlapBgp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the BGP in all Leaf')
         for leaf in testscript.parameters['leaf_list']:
                cfg=''
                for as_no in testscript.parameters['configdict']['bgp_config_dict'][leaf.alias]:
                      cfg+='''router bgp {0}
                              shut
                              no shut
                           '''.format(as_no)
                leaf.configure(cfg)


         time.sleep(350)

         log.info('Verifying traffic after flapping BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM018(aetest.Testcase):

       """MSITE TRM BGW Flap BGP EVPN Neighbors"""
       uid = 'MSITE-TRM-FUNC-018'

       @aetest.test
       def msiteTrmBgwFlapBgpEvpnNeighbors(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the BGP Neighbor in all BGW')
         for bgw in testscript.parameters['bgw_list']:
                cfg=''
                for as_no in testscript.parameters['configdict']['bgp_config_dict'][bgw.alias]:
                      for nei in testscript.parameters['configdict']['bgp_config_dict'][bgw.alias][as_no]['default']['neighbors']['ipv4']:
                     
                           cfg+='''router bgp {0}
                                   neighbor {1}
                                   shut
                                   no shut
                                 '''.format(as_no,nei)
                bgw.configure(cfg)


         time.sleep(350)

         log.info('Verifying traffic after flapping BGP neighbor ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM019(aetest.Testcase):

       """MSITE TRM LEAF Flap BGP EVPN Neighbors"""
       uid = 'MSITE-TRM-FUNC-019'

       @aetest.test
       def msiteTrmLeafFlapBgpEvpnNeighbors(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the BGP Neighbor in all Leaf')
         for leaf in testscript.parameters['leaf_list']:
                cfg=''
                for as_no in testscript.parameters['configdict']['bgp_config_dict'][leaf.alias]:
                      for nei in testscript.parameters['configdict']['bgp_config_dict'][leaf.alias][as_no]['default']['neighbors']['ipv4']:
                     
                           cfg+='''router bgp {0}
                                   neighbor {1}
                                   shut
                                   no shut
                                 '''.format(as_no,nei)
                leaf.configure(cfg)


         time.sleep(350)

         log.info('Verifying traffic after flapping BGP neighbor ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM020(aetest.Testcase):

       """MSITE TRM BGW Clear BGP"""

       uid = 'MSITE-TRM-FUNC-020'

       @aetest.test
       def msiteTrmBgwClearBgp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear ip bgp *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM021(aetest.Testcase):

       """MSITE TRM Leaf Clear BGP"""

       uid = 'MSITE-TRM-FUNC-021'

       @aetest.test
       def msiteTrmLeafClearBgp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear ip bgp *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM022(aetest.Testcase):

       """MSITE TRM BGW Clear ip route"""

       uid = 'MSITE-TRM-FUNC-022'

       @aetest.test
       def msiteTrmBgwClearRoute(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear ip route *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM023(aetest.Testcase):

       """MSITE TRM Leaf Clear ip route"""

       uid = 'MSITE-TRM-FUNC-023'

       @aetest.test
       def msiteTrmLeafClearRoute(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear ip route *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM024(aetest.Testcase):

       """MSITE TRM BGW Clear ip mroute"""

       uid = 'MSITE-TRM-FUNC-024'

       @aetest.test
       def msiteTrmBgwClearMRoute(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear ip mroute *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM025(aetest.Testcase):

       """MSITE TRM Leaf Clear ip mroute"""

       uid = 'MSITE-TRM-FUNC-025'

       @aetest.test
       def msiteTrmLeafClearMRoute(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear ip mroute *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM026(aetest.Testcase):

       """MSITE TRM BGW Clear ip arp"""

       uid = 'MSITE-TRM-FUNC-026'

       @aetest.test
       def msiteTrmBgwClearArp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear ip arp')


         time.sleep(350)

         log.info('Verifying traffic after clear ARP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM027(aetest.Testcase):

       """MSITE TRM Leaf Clear ip arp"""

       uid = 'MSITE-TRM-FUNC-027'

       @aetest.test
       def msiteTrmLeafClearArp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear ip arp')


         time.sleep(350)

         log.info('Verifying traffic after clear ARP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM028(aetest.Testcase):

       """MSITE TRM BGW Clear mac address"""

       uid = 'MSITE-TRM-FUNC-028'

       @aetest.test
       def msiteTrmBgwClearMac(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear mac address-table dynamic')


         time.sleep(350)

         log.info('Verifying traffic after clear mac address')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM029(aetest.Testcase):

       """MSITE TRM Leaf Clear mac"""

       uid = 'MSITE-TRM-FUNC-029'

       @aetest.test
       def msiteTrmLeafClearMac(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear mac address-table dynamic')


         time.sleep(350)

         log.info('Verifying traffic after clear mac address')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM029(aetest.Testcase):

       """MSITE TRM Leaf Clear mac"""

       uid = 'MSITE-TRM-FUNC-029'

       @aetest.test
       def msiteTrmLeafClearMac(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear mac address-table dynamic')


         time.sleep(350)

         log.info('Verifying traffic after clear mac address-table ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM030(aetest.Testcase):

       """MSITE TRM Leaf Flap Uplink"""

       uid = 'MSITE-TRM-FUNC-030'

       @aetest.test
       def msiteTrmLeafFlapUplink(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the Uplink in Leaf')
         result= pcall (vxlan_lib.flapUplink,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping uplink passed')
         else:
                 log.error('Flapping uplink failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after uplink flap ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM031(aetest.Testcase):

       """MSITE TRM Leaf Flap Access-link"""

       uid = 'MSITE-TRM-FUNC-031'

       @aetest.test
       def msiteTrmLeafFlapAccesslink(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the Access link in Leaf')
         result= pcall (vxlan_lib.flapAccesslink,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping Access link passed')
         else:
                 log.error('Flapping Access link failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Access link Flap ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM032(aetest.Testcase):

       """MSITE TRM Leaf Clear ip arp force"""

       uid = 'MSITE-TRM-FUNC-032'

       @aetest.test
       def msiteTrmLeafClearArpForceDelete(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear ip arp force-delete')


         time.sleep(350)

         log.info('Verifying traffic after clear arp forece delete ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')



class MSITETRM033(aetest.Testcase):

       """MSITE TRM Leaf Clear ip pim"""

       uid = 'MSITE-TRM-FUNC-033'

       @aetest.test
       def msiteTrmLeafClearPimRoute(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear ip pim')
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear ip pim route *')


         time.sleep(350)

         log.info('Verifying traffic after clear pim ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')



class MSITETRM034(aetest.Testcase):

       """MSITE TRM BGW Nve Flap """

       uid = 'MSITE-TRM-FUNC-034'

       @aetest.test
       def msiteTrmBgwNveFlap(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Nve Flap on BGW')
         for bgw in testscript.parameters['bgw_list']:
                 cfg=''
                 cfg+='''interface nve1
                         shut
                         no shut
                      '''
                 out=bgw.configure(cfg)
                 if re.search('error|invalid',out,re.I):
                    log.error(f'Nve failed for VTEP {vtep}')
                    self.failed()


         time.sleep(350)

         log.info('Verifying traffic after NVE Flap ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM035(aetest.Testcase):

       """MSITE TRM Leaf Nve Flap """

       uid = 'MSITE-TRM-FUNC-035'

       @aetest.test
       def msiteTrmLeafNveFlap(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Nve Flap on Leaf')
         for leaf in testscript.parameters['leaf_list']:
                 cfg=''
                 cfg+='''interface nve1
                         shut
                         no shut
                      '''
                 out=leaf.configure(cfg)
                 if re.search('error|invalid',out,re.I):
                    log.error(f'Nve failed for VTEP {vtep}')
                    self.failed()


         time.sleep(350)

         log.info('Verifying traffic after NVE Flap ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM036(aetest.Testcase):

       """MSITE TRM BGW Clear bgp l2vpn"""

       uid = 'MSITE-TRM-FUNC-036'

       @aetest.test
       def msiteTrmBgwClearbgpl2vpn(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear Bgp l2vpn route')
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear bgp l2vpn evpn *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM037(aetest.Testcase):

       """MSITE TRM Leaf Clear bgp l2vpn"""

       uid = 'MSITE-TRM-FUNC-037'

       @aetest.test
       def msiteTrmLeafClearBgpl2vpn(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear bgp l2vpn routes')
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear bgp l2vpn evpn *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP l2vpn ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM038(aetest.Testcase):

       """MSITE TRM BGW Clear bgp mvpn"""

       uid = 'MSITE-TRM-FUNC-038'

       @aetest.test
       def msiteTrmBgwClearbgpmvpn(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear Bgp mvpn route')
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear bgp ipv4 mvpn *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP mvpn ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM039(aetest.Testcase):

       """MSITE TRM Leaf Clear bgp mvpn"""

       uid = 'MSITE-TRM-FUNC-039'

       @aetest.test
       def msiteTrmLeafClearBgpmvpn(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear bgp mvpn routes')
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear bgp ipv4 mvpn *')


         time.sleep(350)

         log.info('Verifying traffic after clear BGP mvpn ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM040(aetest.Testcase):

       """MSITE TRM BGW Clear ip igmp snooping"""

       uid = 'MSITE-TRM-FUNC-040'

       @aetest.test
       def msiteTrmBgwClearigmpSnooping(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear igmp snooping')
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear ip igmp snooping groups * vlan all')


         time.sleep(350)

         log.info('Verifying traffic after clear igmp snooping ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM041(aetest.Testcase):

       """MSITE TRM Leaf Clear igmp snooping"""

       uid = 'MSITE-TRM-FUNC-041'

       @aetest.test
       def msiteTrmLeafClearigmpSnooping(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear igmp snooping')
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear ip igmp snooping groups * vlan all')


         time.sleep(350)

         log.info('Verifying traffic after clear igmp snooping ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM042(aetest.Testcase):

       """MSITE TRM BGW Clear ip pim """

       uid = 'MSITE-TRM-FUNC-042'

       @aetest.test
       def msiteTrmBgwClearPim(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear pim')
         for bgw in testscript.parameters['bgw_list']:
                 bgw.execute('clear ip pim route *')


         time.sleep(350)

         log.info('Verifying traffic after clear pim ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM043(aetest.Testcase):

       """MSITE TRM Leaf Pim"""

       uid = 'MSITE-TRM-FUNC-043'

       @aetest.test
       def msiteTrmLeafClearPim(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('clear pim')
         for leaf in testscript.parameters['leaf_list']:
                 leaf.execute('clear ip pim route *')


         time.sleep(350)

         log.info('Verifying traffic after clear pim ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM044(aetest.Testcase):

       """MSITE TRM BGW Nve Source Int Flap """

       uid = 'MSITE-TRM-FUNC-044'

       @aetest.test
       def msiteTrmBgwNveSrcIntFlap(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result= pcall (vxlan_lib.flapNveSourceInt,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Nve Source Int Flap passed')
         else:
                 log.error('Nve Source Int Flap failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Nve Source Int Flap ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM045(aetest.Testcase):

       """MSITE TRM Leaf Nve Source Int Flap"""

       uid = 'MSITE-TRM-FUNC-045'

       @aetest.test
       def msiteTrmLeafNveSrcIntFlap(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result= pcall (vxlan_lib.flapNveSourceInt,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Nve Source Int Flap passed')
         else:
                 log.error('Nve Source Int Flap failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after clear pim ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM046(aetest.Testcase):

       """MSITE TRM BGW Nve Source Int Flap """

       uid = 'MSITE-TRM-FUNC-046'

       @aetest.test
       def msiteTrmBgwNveMsiteSrcIntFlap(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Nve Msite Source Int Flap')
         result= pcall (vxlan_lib.flapNveMsiteSourceInt,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Nve Msite Source Int Flap passed')
         else:
                 log.error('Nve Msite Source Int Flap failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic after Nve Msite Source Int Flap ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM047(aetest.Testcase):

       """MSITE TRM BGW Flap VXLAN VRF """

       uid = 'MSITE-TRM-FUNC-047'

       @aetest.test
       def msiteTrmBgwFlapVrf(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result= pcall (vxlan_lib.flapVxlanVrf,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping of VXLAN VRF passed')
         else:
                 log.error('Flapping of VXLAN VRF failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Flapping the VXLAN VRF')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


class MSITETRM048(aetest.Testcase):

       """MSITE TRM Leaf Flap VXLAN VRF """

       uid = 'MSITE-TRM-FUNC-048'

       @aetest.test
       def msiteTrmLeafFlapVrf(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result= pcall (vxlan_lib.flapVxlanVrf,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping of VXLAN VRF passed')
         else:
                 log.error('Flapping of VXLAN VRF failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Flapping the VXLAN VRF ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM049(aetest.Testcase):

       """MSITE TRM Leaf Flap L2 VNI SVI """

       uid = 'MSITE-TRM-FUNC-049'

       @aetest.test
       def msiteTrmLeafFlapL2VniSvi(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the VXLAN L2 Vni Svi')
         result= pcall (vxlan_lib.flapL2VniSvi,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping the VXLAN L2 Vni Svi passed')
         else:
                 log.error('Flapping the VXLAN L2 Vni Svi failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Flapping the VXLAN L2 Vni Svi ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM050(aetest.Testcase):

       """MSITE TRM Leaf Flap L3 VNI SVI """

       uid = 'MSITE-TRM-FUNC-050'

       @aetest.test
       def msiteTrmLeafFlapL3VniSvi(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the VXLAN L3 Vni Svi')
         result= pcall (vxlan_lib.flapL3VniSvi,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping the VXLAN L3 Vni Svi passed')
         else:
                 log.error('Flapping the VXLAN L3 Vni Svi failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Flapping the VXLAN L3 Vni Svi ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM051(aetest.Testcase):

       """MSITE TRM BGW Flap L3 VNI SVI """

       uid = 'MSITE-TRM-FUNC-051'

       @aetest.test
       def msiteTrmBgwFlapL3VniSvi(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flapping the VXLAN L3 Vni Svi')
         result= pcall (vxlan_lib.flapL3VniSvi,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flapping the VXLAN L3 Vni Svi passed')
         else:
                 log.error('Flapping the VXLAN L3 Vni Svi failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Flapping the VXLAN L3 Vni Svi ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM052(aetest.Testcase):

       """MSITE TRM BGW Suspend and Activate Vxlan Vlan  """

       uid = 'MSITE-TRM-FUNC-052'

       @aetest.test
       def msiteTrmBgwSuspendActivateVlan(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result= pcall (vxlan_lib.SuspendActiveVxlanVlan,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Suspend and Activate Vxlan passed')
         else:
                 log.error('Suspend and Activate Vxlan failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Suspend and Activate Vxlan Vlan ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


class MSITETRM053(aetest.Testcase):

       """MSITE TRM Leaf Suspend and Activate Vxlan Vlan  """

       uid = 'MSITE-TRM-FUNC-053'

       @aetest.test
       def msiteTrmLeafSuspendActivateVlan(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result= pcall (vxlan_lib.SuspendActiveVxlanVlan,log=testscript.parameters['leaf_log_list'],hdl=testscript.parameters['leaf_hdl_list'],dut=testscript.parameters['leaf_dut_list'],configDict=testscript.parameters['leaf_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Suspend and Activate Vxlan passed')
         else:
                 log.error('Suspend and Activate Vxlan failed')
                 self.failed()

         time.sleep(350)

         log.info('Verifying traffic after Suspend and Activate Vxlan Vlan ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM054(aetest.Testcase):

       """MSITE TRM BGW Delete and Add Msite loopback int of NVE"""
       uid = 'MSITE-TRM-FUNC-054'

       @aetest.test
       def msiteTrmBgwAddDeleteMsiteLoopback(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Delete and Add the Msite Loopback interface of Nve')

         result= pcall (vxlan_lib.AddDeleteMsiteNveLoopback,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('NVE Msite loopback remove and add passed')
         else:
                 log.error('NVE Msite loopback remove and add failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM055(aetest.Testcase):

       """MSITE TRM BGW Fabric link Flap"""
       uid = 'MSITE-TRM-FUNC-055'

       @aetest.test
       def msiteTrmBgwFabricLinkFlap(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flap Fabric link')

         result= pcall (vxlan_lib.flapMsiteFabricLink,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flap Fabric link passed')
         else:
                 log.error('Flap Fabric link failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic after Flapping Fabric link ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM056(aetest.Testcase):

       """MSITE TRM BGW :DCI link Flap"""
       uid = 'MSITE-TRM-FUNC-056'

       @aetest.test
       def msiteTrmBgwDciLinkFlap(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Flap DCI link')

         result= pcall (vxlan_lib.flapMsiteDciLink,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Flap DCI link passed')
         else:
                 log.error('Flap DCI link failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic after Flapping DCI link ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM057(aetest.Testcase):

       """MSITE TRM BGW Add / Remove Fabric track"""
       uid = 'MSITE-TRM-FUNC-057'

       @aetest.test
       def msiteTrmBgwAddRemoveFabricTrack(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Remove and Add Fabric Track')

         result= pcall (vxlan_lib.AddRemoveFabricTrack,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Removing and Adding Fabric track passed')
         else:
                 log.error('Removing and Adding Fabric track failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic after Remove and Add Fabric Track ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM058(aetest.Testcase):

       """MSITE TRM BGW Add / Remove DCI track"""
       uid = 'MSITE-TRM-FUNC-058'

       @aetest.test
       def msiteTrmBgwAddRemoveDciTrack(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Remove and Add DCI Track')

         result= pcall (vxlan_lib.AddRemoveDciTrack,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Removing and Adding Fabric track passed')
         else:
                 log.error('Removing and Adding Fabric track failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic after Remove and Add Fabric Track ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM059(aetest.Testcase):

       """MSITE TRM BGW Remove and Add Msite IR under L2 vni in NVE"""
       uid = 'MSITE-TRM-FUNC-059'

       @aetest.test
       def msiteTrmBgwAddRemoveMsiteIRL2vniNve(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Remove and Add Msite IR under L2 vni in NVE')

         result= pcall (vxlan_lib.addRemoveNveMsiteIRL2vni,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Remove and Add Msite IR under L2 vni in NVE passed')
         else:
                 log.error('Remove and Add Msite IR under L2 vni in NVE failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic after Remove and Add Msite IR under L2 vni in NVE ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM060(aetest.Testcase):

       """MSITE TRM BGW Remove and Addi TRM Msite IR under L3 vni in NVE"""
       uid = 'MSITE-TRM-FUNC-060'

       @aetest.test
       def msiteTrmBgwAddRemoveMsiteIRL3vniNve(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Remove and Add TRM Msite IR under L3 vni in NVE')

         result= pcall (vxlan_lib.addRemoveNveTrmMsiteIRL3vni,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Remove and Add TRM Msite IR under L3 vni in NVE passed')
         else:
                 log.error('Remove and Add TRM Msite IR under L3 vni in NVE failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic after Remove and Add TRM Msite IR under L3 vni in NVE ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM061(aetest.Testcase):

       """MSITE TRM BGW Remove and Add Msite GW"""
       uid = 'MSITE-TRM-FUNC-061'

       @aetest.test
       def msiteTrmBgwAddRemoveMsiteGw(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Remove and Add Msite GW ')

         result= pcall (vxlan_lib.addRemoveMsiteBorderGw,log=testscript.parameters['bgw_log_list'],hdl=testscript.parameters['bgw_hdl_list'],dut=testscript.parameters['bgw_dut_list'],configDict=testscript.parameters['bgw_configdict_list'])

         if testscript.parameters['fail_result'] not in result:
                 log.info('Remove and Add  Msite GW passed')
         else:
                 log.error('Remove and Add  Msite GW failed')
                 self.failed()


         time.sleep(350)

         log.info('Verifying traffic after Remove and Add Msite GW ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM062(aetest.Testcase):

       """MSITE TRM BGW Restart BGP"""

       uid = 'MSITE-TRM-FUNC-062'

       @aetest.test
       def msiteTrmBgwRestartBgp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart BGP')
         for hdl,bgw in zip(testscript.parameters['bgw_hdl_list'],testscript.parameters['bgw_dut_list']):
              for as_no in list(testscript.parameters['configdict']['bgp_config_dict'][bgw].keys()):
                 cfg=''
                 cfg+='''restart bgp {0}
                      '''.format(as_no)
              hdl.execute(cfg,timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after restart BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM063(aetest.Testcase):

       """MSITE TRM Leaf Restart BGP"""

       uid = 'MSITE-TRM-FUNC-063'

       @aetest.test
       def msiteTrmLeafRestartBgp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart BGP')

         for hdl,leaf in zip(testscript.parameters['leaf_hdl_list'],testscript.parameters['leaf_dut_list']):
              for as_no in list(testscript.parameters['configdict']['bgp_config_dict'][leaf].keys()):
                 cfg=''
                 cfg+='''restart bgp {0}
                      '''.format(as_no)
              hdl.execute(cfg,timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after Restart BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM064(aetest.Testcase):

       """MSITE TRM BGW Restart Ospf"""

       uid = 'MSITE-TRM-FUNC-064'

       @aetest.test
       def msiteTrmBgwRestartOspf(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart Ospf')
         for hdl,bgw in zip(testscript.parameters['bgw_hdl_list'],testscript.parameters['bgw_dut_list']):
              for tag in list(testscript.parameters['configdict']['ospfv2_config_dict'][bgw].keys()):
                 cfg=''
                 cfg+='''restart ospf {0}
                      '''.format(tag)
              hdl.execute(cfg,timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after restart Ospf ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM065(aetest.Testcase):

       """MSITE TRM Leaf Restart Ospf"""

       uid = 'MSITE-TRM-FUNC-065'

       @aetest.test
       def msiteTrmLeafRestartOspf(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart Ospf')

         for hdl,leaf in zip(testscript.parameters['leaf_hdl_list'],testscript.parameters['leaf_dut_list']):
              for tag in list(testscript.parameters['configdict']['ospfv2_config_dict'][leaf].keys()):
                 cfg=''
                 cfg+='''restart ospf {0}
                      '''.format(tag)
              hdl.execute(cfg,timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after Restart BGP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM066(aetest.Testcase):

       """MSITE TRM BGW Restart Pim"""

       uid = 'MSITE-TRM-FUNC-066'

       @aetest.test
       def msiteTrmBgwRestartPim(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart Pim')
         for bgw in testscript.parameters['bgw_list']:
              bgw.execute('restart pim',timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after restart Pim ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM067(aetest.Testcase):

       """MSITE TRM Leaf Restart Pim"""

       uid = 'MSITE-TRM-FUNC-067'

       @aetest.test
       def msiteTrmLeafRestartPim(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart Pim')

         for leaf in testscript.parameters['leaf_list']:
              leaf.execute('restart pim',timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after Restart Pim ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM068(aetest.Testcase):

       """MSITE TRM BGW Restart NGMVPN"""

       uid = 'MSITE-TRM-FUNC-068'

       @aetest.test
       def msiteTrmBgwRestartNgmvpn(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart NGMVPN')
         for bgw in testscript.parameters['bgw_list']:
              bgw.execute('restart ngmvpn',timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after restart NGMVPN ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM069(aetest.Testcase):

       """MSITE TRM Leaf Restart NGMVPN"""

       uid = 'MSITE-TRM-FUNC-069'

       @aetest.test
       def msiteTrmLeafRestartNgmvpn(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart NGMVPN')

         for leaf in testscript.parameters['leaf_list']:
              leaf.execute('restart ngmvpn',timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after Restart NGMVPN ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM070(aetest.Testcase):

       """MSITE TRM BGW Restart IGMP"""

       uid = 'MSITE-TRM-FUNC-070'

       @aetest.test
       def msiteTrmBgwRestartIgmp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart IGMP')
         for bgw in testscript.parameters['bgw_list']:
              bgw.execute('restart igmp',timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after restart IGMP')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM071(aetest.Testcase):

       """MSITE TRM Leaf Restart IGMP"""

       uid = 'MSITE-TRM-FUNC-071'

       @aetest.test
       def msiteTrmLeafRestartIgmp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Restart IGMP')

         for leaf in testscript.parameters['leaf_list']:
              leaf.execute('restart igmp',timeout=200)


         time.sleep(350)

         log.info('Verifying traffic after Restart IGMP ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


class MSITETRM072(aetest.Testcase):

       """MSITE TRM BGW Process Kill L2fm"""

       uid = 'MSITE-TRM-FUNC-072'

       @aetest.test
       def msiteTrmBgwProcessL2fm(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('L2fm Process Kill')
         for bgw in testscript.parameters['bgw_list']:
               if vxlan_lib.ProcessRestart(bgw, 'l2fm'):
                    log.info(f'Process restart of l2fm done as expected on {bgw}')
               else:
                    log.error(f'Process restart of l2fm failed in on {bgw}')

         time.sleep(350)

         log.info('Verifying traffic after L2fm Process Kill ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM073(aetest.Testcase):

       """MSITE TRM Leaf L2fm Process Kill"""

       uid = 'MSITE-TRM-FUNC-073'

       @aetest.test
       def msiteTrmLeafProcessL2fm(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('L2FM Process Kill')

         for leaf in testscript.parameters['leaf_list']:
               if vxlan_lib.ProcessRestart(leaf, 'l2fm'):
                    log.info(f'Process restart of l2fm done as expected on {leaf}')
               else:
                    log.error(f'Process restart of l2fm failed in on {leaf}')

         time.sleep(350)

         log.info('Verifying traffic after L2FM Process Kill')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM074(aetest.Testcase):

       """MSITE TRM BGW Process Kill L2rib"""

       uid = 'MSITE-TRM-FUNC-074'

       @aetest.test
       def msiteTrmBgwProcessL2rib(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('L2rib Process Kill')
         for bgw in testscript.parameters['bgw_list']:
               if vxlan_lib.ProcessRestart(bgw,'l2rib'):
                    log.info(f'Process restart of l2rib done as expected on {bgw}')
               else:
                    log.error(f'Process restart of l2rib failed in on {bgw}')

         time.sleep(350)

         log.info('Verifying traffic after L2rib Process Kill ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM075(aetest.Testcase):

       """MSITE TRM Leaf L2rib Process Kill"""

       uid = 'MSITE-TRM-FUNC-075'

       @aetest.test
       def msiteTrmLeafProcessL2rib(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('L2rib Process Kill')

         for leaf in testscript.parameters['leaf_list']:
               if vxlan_lib.ProcessRestart(leaf,'l2rib'):
                    log.info(f'Process restart of l2rib done as expected on {leaf}')
               else:
                    log.error(f'Process restart of l2rib failed in on {leaf}')

         time.sleep(350)

         log.info('Verifying traffic after L2Rib Process Kill')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM076(aetest.Testcase):

       """MSITE TRM BGW Process Kill nve"""

       uid = 'MSITE-TRM-FUNC-076'

       @aetest.test
       def msiteTrmBgwProcessNve(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Nve Process Kill')
         for bgw in testscript.parameters['bgw_list']:
               if vxlan_lib.ProcessRestart(bgw,'nve'):
                    log.info(f'Process restart of nve done as expected on {bgw}')
               else:
                    log.error(f'Process restart of nve failed in on {bgw}')

         time.sleep(350)

         log.info('Verifying traffic after NVE Process Kill ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM077(aetest.Testcase):

       """MSITE TRM Leaf NVE Process Kill"""

       uid = 'MSITE-TRM-FUNC-077'

       @aetest.test
       def msiteTrmLeafProcessNve(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Nve Process Kill')

         for leaf in testscript.parameters['leaf_list']:
               if vxlan_lib.ProcessRestart(leaf,'nve'):
                    log.info(f'Process restart of Nve done as expected on {leaf}')
               else:
                    log.error(f'Process restart of Nve failed in on {leaf}')

         time.sleep(350)

         log.info('Verifying traffic after NVE Process Kill')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM078(aetest.Testcase):

       """MSITE TRM BGW Process Kill NGMVPN"""

       uid = 'MSITE-TRM-FUNC-078'

       @aetest.test
       def msiteTrmBgwProcessNgmvpn(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Ngmvpn Process Kill')
         for bgw in testscript.parameters['bgw_list']:
               if vxlan_lib.ProcessRestart(bgw,'ngmvpn'):
                    log.info(f'Process restart of NGMVPN done as expected on {bgw}')
               else:
                    log.error(f'Process restart of NGMVPN failed in on {bgw}')

         time.sleep(350)

         log.info('Verifying traffic after NGMVPN Process Kill ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM079(aetest.Testcase):

       """MSITE TRM Leaf NGMVPN Process Kill"""

       uid = 'MSITE-TRM-FUNC-079'

       @aetest.test
       def msiteTrmLeafProcessNgmvpn(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('NGMVPN Process Kill')

         for leaf in testscript.parameters['leaf_list']:
               if vxlan_lib.ProcessRestart(leaf,'ngmvpn'):
                    log.info(f'Process restart of NGMVPN done as expected on {leaf}')
               else:
                    log.error(f'Process restart of NGMVPN failed in on {leaf}')

         time.sleep(350)

         log.info('Verifying traffic after NGMVPN Process Kill')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM080(aetest.Testcase):

       """MSITE TRM BGW Process Kill BGP"""

       uid = 'MSITE-TRM-FUNC-080'

       @aetest.test
       def msiteTrmBgwProcessBgp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('BGP Process Kill')
         for bgw in testscript.parameters['bgw_list']:
               if vxlan_lib.ProcessRestart(bgw,'bgp'):
                    log.info(f'Process restart of BGP done as expected on {bgw}')
               else:
                    log.error(f'Process restart of BGP failed in on {bgw}')

         time.sleep(350)

         log.info('Verifying traffic after BGP Process Kill ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM081(aetest.Testcase):

       """MSITE TRM Leaf BGP Process Kill"""

       uid = 'MSITE-TRM-FUNC-081'

       @aetest.test
       def msiteTrmLeafProcessBgp(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('BGP Process Kill')

         for leaf in testscript.parameters['leaf_list']:
               if vxlan_lib.ProcessRestart(leaf,'bgp'):
                    log.info(f'Process restart of BGP done as expected on {leaf}')
               else:
                    log.error(f'Process restart of BGP failed in on {leaf}')

         time.sleep(350)

         log.info('Verifying traffic after BGP Process Kill')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM082(aetest.Testcase):

       """MSITE TRM BGW Process Kill OSPF"""

       uid = 'MSITE-TRM-FUNC-082'

       @aetest.test
       def msiteTrmBgwProcessOspf(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('OSPF Process Kill')
         for bgw in testscript.parameters['bgw_list']:
               if vxlan_lib.ProcessRestart(bgw,'ospf'):
                    log.info(f'Process restart of OSPF done as expected on {bgw}')
               else:
                    log.error(f'Process restart of OSPF failed in on {bgw}')

         time.sleep(350)

         log.info('Verifying traffic after OSPF Process Kill ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM083(aetest.Testcase):

       """MSITE TRM Leaf OSPF Process Kill"""

       uid = 'MSITE-TRM-FUNC-083'

       @aetest.test
       def msiteTrmLeafProcessOspf(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('OSPF Process Kill')

         for leaf in testscript.parameters['leaf_list']:
               if vxlan_lib.ProcessRestart(leaf,'ospf'):
                    log.info(f'Process restart of OSPF done as expected on {leaf}')
               else:
                    log.error(f'Process restart of OSPF failed in on {leaf}')

         time.sleep(350)

         log.info('Verifying traffic after OSPF Process Kill')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM084(aetest.Testcase):

       """MSITE TRM BGW Sit1 BGW Reload"""

       uid = 'MSITE-TRM-FUNC-084'

       @aetest.test
       def msiteTrmSite1BGW1Reload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload uut1 of Site1')
        
         testscript.parameters['uut1'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut1'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


class MSITETRM085(aetest.Testcase):

       """MSITE TRM BGW Site1 BGW Reload"""

       uid = 'MSITE-TRM-FUNC-085'

       @aetest.test
       def msiteTrmSite1BGW2Reload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload uut2 of Site1')
        
         testscript.parameters['uut2'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut2'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM086(aetest.Testcase):

       """MSITE TRM BGW Site2 BGW Reload"""

       uid = 'MSITE-TRM-FUNC-086'

       @aetest.test
       def msiteTrmSite2BGW1Reload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload uut3 of Site2')
        
         testscript.parameters['uut3'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut3'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM087(aetest.Testcase):

       """MSITE TRM BGW Site2 BGW Reload"""

       uid = 'MSITE-TRM-FUNC-087'

       @aetest.test
       def msiteTrmSite2BGW2Reload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload uut4 of Site2')
        
         testscript.parameters['uut4'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut4'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM088(aetest.Testcase):

       """MSITE TRM BGW Site3 BGW Reload"""

       uid = 'MSITE-TRM-FUNC-088'

       @aetest.test
       def msiteTrmSite3BGWReload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload uut5 of Site2')
        
         testscript.parameters['uut5'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut5'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM089(aetest.Testcase):

       """MSITE TRM Site1 Leaf Reload"""

       uid = 'MSITE-TRM-FUNC-089'

       @aetest.test
       def msiteTrmSite1LeafReload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload Leaf uut9 of Site1')
        
         testscript.parameters['uut9'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut9'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM090(aetest.Testcase):

       """MSITE TRM Site2 Leaf Reload"""

       uid = 'MSITE-TRM-FUNC-090'

       @aetest.test
       def msiteTrmSite2LeafReload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload Leaf uut10 of Site1')
        
         testscript.parameters['uut10'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut10'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM091(aetest.Testcase):

       """MSITE TRM Site3 Leaf Reload"""

       uid = 'MSITE-TRM-FUNC-091'

       @aetest.test
       def msiteTrmSite3LeafReload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload Leaf uut11 of Site1')
        
         testscript.parameters['uut11'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut11'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


class MSITETRM092(aetest.Testcase):

       """MSITE TRM Site1 Spine Reload"""

       uid = 'MSITE-TRM-FUNC-092'

       @aetest.test
       def msiteTrmSite1SpineReload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload Spine uut7 of Site1')
        
         testscript.parameters['uut7'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut7'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(350)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM093(aetest.Testcase):

       """MSITE TRM Site2 Spine Reload"""

       uid = 'MSITE-TRM-FUNC-093'

       @aetest.test
       def msiteTrmSite2SpineReload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload Spine uut8 of Site1')
        
         testscript.parameters['uut8'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut8'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(350)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')

class MSITETRM094(aetest.Testcase):

       """MSITE TRM DCI Reload"""

       uid = 'MSITE-TRM-FUNC-094'

       @aetest.test
       def msiteTrmSite2SpineReload(self,log,testscript,testbed):

            
         log.info('Starting the traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'start')

         log.info('Starting the BUM traffic')
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['bum_config'],testscript.parameters['bum_handle_dict'],'start')

         time.sleep(120)

         log.info('Verifying traffic ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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

         log.info('Reload DCI')
        
         testscript.parameters['uut15'].execute('copy r s',timeout=120)
 
         testscript.parameters['uut15'].reload(prompt_recovery=True, timeout=1200)

         time.sleep(500)

         log.info('Verifying traffic after reload ')

         if tgnConfig_lib.verifyMcastTrafficDrop(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['configdict']['traffic_config_dict']['igmp_config'],testscript.parameters['mcast_traffic_handle_dict']):
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
         result=tgnConfig_lib.tgn_traffic(log,testscript.parameters['tgen'],testscript.parameters['configdict']['traffic_config_dict']['traffic_config']['mcast_bound'],testscript.parameters['mcast_traffic_handle_dict'],'stop')


