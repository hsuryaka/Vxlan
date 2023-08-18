import os
import sys
import yaml
import re
import utils
from utils import *
import  bringup_lib
import parserutils_lib
import verify_lib


class configTcam():

    def __init__(self,tcam_config_dict,switch_hdl_dict,log):
        self.log=log
        self.result='pass'
        self.tcam_config_dict=tcam_config_dict
        self.switch_hdl_dict=switch_hdl_dict

        try:
           self.list_of_nodes=self.tcam_config_dict.keys()
        except KeyError:
           err_msg='Error !!! tcam_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
           testResult( 'fail', err_msg, self.log )

    def AllNodes(self):
        for node in self.list_of_nodes:
           self.Nodes(node)


    def Nodes(self,node):
        self.log.info(node)
        hdl=self.switch_hdl_dict[node]
        if hdl.type in ['N35K']:

           for region in self.tcam_config_dict[node].keys():
               hdl.configure('hardware profile tcam region {0} 0'.format(region))
           
           for region in self.tcam_config_dict[node].keys():
               hdl.configure('hardware profile tcam region {0} {1}'.format(region,self.tcam_config_dict[node][region]))
           hdl.execute('copy r s')
           self.log.info('Reloading of devices')
           reload_result=hdl.reload()
           print('################')
           print (reload_result)   
           out=hdl.execute('show hardware profile tcam region')
           tcam_values=re.findall('(\S+)\s+size\s+\=\s+(\d+)',out)

           tcam_out_dict=dict((a[0],a[1]) for a in iter(tcam_values))

           self.log.info('Comparing config dict with actual dict after reboot')
           for region in self.tcam_config_dict[node].keys():
                   if int(tcam_out_dict[region]) != self.tcam_config_dict[node][region]:
                         self.log.error('Tcam region not matching for {0}'.format(region))
                         return 0

        elif hdl.type in ['N3K','N9K']:
                cfg=''
                order_cfg={}
                for region in self.tcam_config_dict[node].keys():
                   arggrammar={}
                   arggrammar['size']='-type int -required true'
                   arggrammar['double_wide']='-type bool -default False'
                   arggrammar['order']='-type int -default 0'
                   ns=parserutils_lib.argsToCommandOptions( self.tcam_config_dict[node][region], arggrammar, self.log )
                   double_wide=''
                   if ns.double_wide:
                       double_wide='double-wide'
                   if ns.order==0:
                       hdl.configure ('hardware access-list tcam region {0} {1} {2}'.format(region,ns.size,double_wide))
                   else:
                       order_cfg[ns.order]='hardware access-list tcam region {0} {1} {2}'.format(region,ns.size,double_wide)
                cfg=''      
                for key in order_cfg.keys():
                         cfg+=order_cfg[key]
                hdl.configure(cfg)
                log.info('Reloading the box after Carving TCAM')
                hdl.execute('copy r s')
                reload_result=hdl.reload()
                if reload_result:
                       log.info('Reloading the box after Carving TCAM is successful')
                       return 1
                else:
                       log.error('Reloading of box is not successful after TCAM carving')
                       return 0
