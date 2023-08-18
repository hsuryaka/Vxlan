import logging
from ats.log.utils import banner
from common_lib import utils
from common_lib.utils import *
import threading
import random
from bs4 import BeautifulSoup
import time

class TriggerItems:

    # First we create a constructor for this class
    # and add members to it, here models
    def __init__(self,log, node_dict,configdict,traffic_stream_dict,port_handle_dict,threshold,alias_intf_mapping,configured_stream):
        self.log = log
        self.node_dict = node_dict
        self.configdict = configdict
        self.traffic_stream_dict = traffic_stream_dict
        self.port_handle_dict = port_handle_dict
        self.threshold = threshold
        self.alias_intf_mapping = alias_intf_mapping
        self.configured_stream = configured_stream
        self.configsuccess = 1
        
    def getDeviceDict(self,*args):
        dut = args
        self.dev_dict = {}
        for item in dut:
            if item == 'all_vtep':
                res = {k : v for k,v in self.node_dict.items() if 'vtep' in k}
                for k, v in res.items():
                    self.dev_dict.update(v)
            elif item =='stand_vtep':
                self.dev_dict = self.node_dict['stand_vteps']
            elif item == 'vpc_vtep':
                self.dev_dict = self.node_dict['vpc_vteps']
            elif item == 'l2_switch':
                self.dev_dict = self.node_dict['l2_switch']
            elif item == 'spines':
                self.dev_dict = self.node_dict['spines']
            self.log.info('The value of dev_dict is : {0}'.format(self.dev_dict))
        return self.dev_dict
 
    def configUnconfigL2VNIOnNVE(self,**data):
        if data['mode']:
            threads = []
            for dut in self.dev_dict:
                hdl = self.dev_dict[dut]
                t = threading.Thread(target = nveInterfaceMemberVniConfigUnconfig, args = [self.log,hdl,self.configdict['scale_config_dict'][dut]['global']['vlan'],data['mode']])
                t.start()
                threads.append(t)
            for thread in threads:
                thread.join()
                
    
    def changeInterfaceSwitchPortMode(self,dut_hdl,intf,vlan,mode,**kwargs):
        self.log.info('Inside ChangeInterfaceSwitchPortMode')
        if kwargs:
            po_no = kwargs['po_no']
            res = cfgIntfSwtichPortMode(self.log,dut_hdl,intf,mode,vlan,po_no)
        else:
            res = cfgIntfSwtichPortMode(self.log,dut_hdl,intf,mode,vlan)
        if res:
            return 1
    
    def getAllBoundStreamStats(self):
        pass
    
    def getAllRawStreamStats(self):
        self.log.info('Inside getAllRawStreamStats')
        pass
    
    def individualBoundStreamStats(self):
        pass
    
    def getRawStreamStatsbyStreamID(self,tgn_hdl,traffic_to_consider):
        self.log.info('Inside getRawStreamStatsbyStreamID')
        for x in traffic_to_consider:
            res = get
    
    def checkAllStreamStats(self,tgn_hdl):
        self.log.info('Inside checkAllStreamStats')
        self.log.info('The value of tgn_hdl is : {0}'.format(tgn_hdl))
        overall_status = 1
        failed_streams = []
        for trf in self.configured_stream:
            self.log.info('The value of trf is : {0}'.format(trf))
            self.log.info('The value of trf inside regex is : {0}'.format(trf))
            res = getTrafficItemStatisticsIdeal(self.log,tgn_hdl,self.traffic_stream_dict,trf,self.threshold)
            self.log.info('The value of res inside regex is : {0}'.format(res))
            if res:
                self.log.info(banner('Traffic Stream {0} Flow is as expected - '.format(trf)))
            else:
                failed_streams.append(trf)
            time.sleep(1)
        if not failed_streams:
            return 1
        return 0


    def checkAllRawStreamStatsTrigger(self,tgn_hdl,dev_len,trigger_type,no_of_vlan,**vlan_list):
        self.log.info('Inside checkAllStreamStatsTRigger')
        self.log.info('The value of tgn_hdl is : {0}'.format(tgn_hdl))
        failed_streams = []
        status_dict = {}
        if vlan_list:
            self.log.info(banner('The value of vlan_list is : {0}'.format(vlan_list)))
            if 'allowed_vlan' in vlan_list.keys():
                allowed_vlan = vlan_list['allowed_vlan']
            if 'traffic_list' in vlan_list.keys():
                self.configured_stream = vlan_list['traffic_list']
        self.log.info(banner('Value of Configured Stream is : {0}'.format(self.configured_stream)))
        for trf in self.configured_stream:
            if re.search('RAW',trf):
                self.log.info('The value of trf is : {0}'.format(trf))
                self.log.info('The value of trf inside regex is : {0}'.format(trf))
                if vlan_list:
                    self.log.info(banner('The value of vlan_list is : {0}'.format(vlan_list)))
                    if 'allowed_vlan' in vlan_list.keys():
                        res = getRawTrafficItemStatisticsTrigger(self.log,tgn_hdl,self.traffic_stream_dict,trf,self.threshold,dev_len,trigger_type,no_of_vlan,allowed_vlan)
                    elif 'traffic_list' in vlan_list.keys():
                        res = getRawTrafficItemStatisticsTrigger(self.log,tgn_hdl,self.traffic_stream_dict,trf,self.threshold,dev_len,trigger_type,no_of_vlan)
                else:
                    res = getRawTrafficItemStatisticsTrigger(self.log,tgn_hdl,self.traffic_stream_dict,trf,self.threshold,dev_len,trigger_type,no_of_vlan)
                self.log.info('The value of res inside regex is : {0}'.format(res))
                if res:
                    self.log.info(banner('Traffic Stream {0} Flow is as expected - '.format(trf)))
                else:
                    failed_streams.append(trf)
        if not failed_streams:
            status_dict['status'] = 1
            status_dict['streams'] = failed_streams
        else:
            status_dict['status'] = 0
            status_dict['streams'] = failed_streams
        return status_dict
        
    def getVPCSwitchhdl(self,vpc_device):
        self.log.info('Inside class getVPCPrimarySwitchhdl')
        vpc_switches = self.node_dict['vpc_vteps']
        self.log.info('The value of vpc_switches is : {0}'.format(vpc_switches))
        a = returnVPCSwitchHandle(self.log,vpc_switches)
        if a: 
            if re.search('primary',vpc_device):
                return a['primary']['hdl']
            if re.search('secondary',vpc_device):
                return a['secondary']['hdl']
            if re.search('details',vpc_device):
                return a
                

    def backUpAndRestoreConfigs(self,devices,mode):
        for i in devices:
            hdl = self.node_dict['all_dut'][i]
            res = configBackUpOrRestoreOrCleanUp(self.log,hdl,mode)
            
    def defaultSetOfInterfaces(self,hdl,interfaces):
        for intf in interfaces:
            res = defaultInterface(self.log,hdl,intf)
        return 1
    
    def configurePo(self,hdl,intf,args):
        res = configurePortChannel(self.log,hdl,intf,args,self.alias_intf_mapping)
        if res:
            return 1
        return 0
        
    def configureSVI(self,hdl,intf,args):
        res = configureSVIInterface(self.log,hdl,intf,args,self.alias_intf_mapping)
        if res:
            return 1
        return 0

    def configureSVINonNve(self,hdl,intf,args):
        res = configureSVIInterfaceNonNve(self.log,hdl,intf,args,self.alias_intf_mapping)
        if res:
            return 1
        return 0



def parseSVIConfigParams(log,args):
    log.info('Inside the parseSVIConfigParams function()')
    arggrammar={}
    arggrammar['memberlist'] = '-type str'
    arggrammar['mode'] = '-type str'
    arggrammar['switchportmode'] = '-type str'
    arggrammar['allowed_vlan_list'] = '-type str'
    arggrammar['ipv4_addr'] = '-type str'
    arggrammar['ipv6_addr'] = '-type str'
    arggrammar['ospf'] = '-type bool'
    arggrammar['ospfv3'] = '-type bool'
    arggrammar['pim_state'] = '-type bool'
    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def configureSVIInterfaceNonNve(log,hdl,intf,args,alias_intf_mapping):
    ns = parseSVIConfigParams(log,args)
    log.info('the value of ns is : {0}'.format(ns))
    log.info('the value if intf is : {0}'.format(intf))
    if re.search('uut',ns.memberlist):
        member = alias_intf_mapping[ns.memberlist]
    else:
        member = ns.memberlist
    vlan_no = re.search('vlan(\d+)',intf).group(1)
    log.info('Converting the interface {0} into SVI'.format(member))
    cfg = '''interface {0}
             switchport
             switchport mode {1}
             switchport trunk allowed vlan {2}
             load-interval counter 1 5 
             load-interval counter 2 10 
             load-interval counter 3 15 
             no shutdown'''.format(member,ns.switchportmode,ns.allowed_vlan_list)
    hdl.configure(cfg)
    cfg1 = '''vlan {0}
              exit
              interface vlan {0}
              no shutdown
           '''.format(vlan_no) + '\n'
    
    if ns.ipv4_addr:
        cfg1 += 'ip address {0}'.format(ns.ipv4_addr) + '\n'
    if ns.ipv6_addr:
        cfg1 += 'ipv6 address {0}'.format(ns.ipv6_addr) + '\n'
    if ns.ospf:
        cfg1 += '''ip router ospf vxlan area 0
                   ip ospf dead-interval 4
                   ip ospf hello-interval 1''' + '\n'
    if ns.ospfv3:
        cfg1 += '''ipv6 router ospfv3 vxlan area 0.0.0.0
                   ospfv3 dead-interval 4
                   ospfv3 hello-interval 1''' + '\n'
    if ns.pim_state:
        cfg1 += 'ip pim sparse-mode \n'
                   
    log.info('The value of cfg1 is : {0}'.format(cfg1))
    hdl.configure(cfg1)
    return 1

def configureSVIInterface(log,hdl,intf,args,alias_intf_mapping):
    ns = parseSVIConfigParams(log,args)
    log.info('the value of ns is : {0}'.format(ns))
    log.info('the value if intf is : {0}'.format(intf))
    if re.search('uut',ns.memberlist):
        member = alias_intf_mapping[ns.memberlist]
    else:
        member = ns.memberlist
    vlan_no = re.search('vlan(\d+)',intf).group(1)
    log.info('Converting the interface {0} into SVI'.format(member))
    cfg = '''interface {0}
             switchport
             switchport mode {1}
             switchport trunk allowed vlan {2}
             load-interval counter 1 5 
             load-interval counter 2 10 
             load-interval counter 3 15 
             no shutdown'''.format(member,ns.switchportmode,ns.allowed_vlan_list)
    hdl.configure(cfg)
    cfg1 = '''vlan {0}
              exit
              system nve infra-vlans {0}
              interface vlan {0}
              no shutdown
           '''.format(vlan_no) + '\n'
    
    if ns.ipv4_addr:
        cfg1 += 'ip address {0}'.format(ns.ipv4_addr) + '\n'
    if ns.ipv6_addr:
        cfg1 += 'ipv6 address {0}'.format(ns.ipv6_addr) + '\n'
    if ns.ospf:
        cfg1 += '''ip router ospf vxlan area 0
                   ip ospf dead-interval 4
                   ip ospf hello-interval 1''' + '\n'
    if ns.ospfv3:
        cfg1 += '''ipv6 router ospfv3 vxlan area 0.0.0.0
                   ospfv3 dead-interval 4
                   ospfv3 hello-interval 1''' + '\n'
    if ns.pim_state:
        cfg1 += 'ip pim sparse-mode \n'
                   
    log.info('The value of cfg1 is : {0}'.format(cfg1))
    hdl.configure(cfg1)
    return 1

def parsePortChannelParams(log,args):
    log.info('Inside the parsePortChannelParams function()')
    arggrammar={}
    arggrammar['memberlist'] = '-type str'
    arggrammar['mode'] = '-type str'
    arggrammar['ipv4_addr'] = '-type str'
    arggrammar['ipv4_prf_len'] = '-type str'
    arggrammar['ipv6_addr'] = '-type str'
    arggrammar['ipv6_prf_len'] = '-type str'
    arggrammar['ospf'] = '-type bool'
    arggrammar['ospfv3'] = '-type bool'
    arggrammar['pim_state'] = '-type bool'
    arggrammar['tunnel_encryption'] = '-type bool'
    arggrammar['dci_tracking'] = '-type bool'
    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def configurePortChannel(log,hdl,intf,args,alias_intf_mapping):
    ns = parsePortChannelParams(log,args)
    log.info('the value of ns is : {0}'.format(ns))
    log.info('the value if intf is : {0}'.format(intf))
    channel_no = re.search('port-channel(\d+)',intf).group(1)
    for member in ns.memberlist.split():
        if re.search('uut',member):
            intf = alias_intf_mapping[member]
        else:
            intf = member
        log.info('Converting the interface {0} into port-channel'.format(intf))
        cfg = '''interface {0}
                 {1}
                 channel-group {2} force mode active
                 no shutdown'''.format(intf,ns.mode,channel_no)
        hdl.configure(cfg)
    cfg1 = '''interface port-channel {0}
              no shutdown
              load-interval counter 1 5 
              load-interval counter 2 10
              load-interval counter 3 15'''.format(channel_no) + '\n'
    
    if ns.ipv4_addr and ns.ipv4_prf_len:
        cfg1 += 'ip address {0}/{1}'.format(ns.ipv4_addr,ns.ipv4_prf_len) + '\n'
    if ns.ipv6_addr and ns.ipv6_prf_len:
        cfg1 += 'ipv6 address {0}/{1}'.format(ns.ipv6_addr,ns.ipv6_prf_len) + '\n'
    if ns.ospf:
        cfg1 += '''ip router ospf vxlan area 0
                   ip ospf dead-interval 4
                   ip ospf hello-interval 1''' + '\n'
    if ns.ospfv3:
        cfg1 += '''ipv6 router ospfv3 vxlan area 0.0.0.0
                   ospfv3 dead-interval 4
                   ospfv3 hello-interval 1''' + '\n'
                   
    if ns.pim_state:
        cfg1 += 'ip pim sparse-mode \n'
        
    if ns.tunnel_encryption:
        cfg1 += 'tunnel-encryption \n'
        
    if ns.dci_tracking:
        cfg1 += 'evpn multisite dci-tracking \n'
                   
    log.info('The value of cfg1 is : {0}'.format(cfg1))
    hdl.configure(cfg1)
    return 1


def conifgureEthInterface(log,hdl,args):
    log.info('configuring Ethernet Interfaces with args : {0}'.format(args))
    
                 
            
def defaultInterface(log,hdl,intf):
    log.info('Defaulting the Interface : {0}'.format(intf))
    cmd = 'default interface {0}'.format(intf)
    hdl.configure(cmd, timeout = 300)
    return 1
            

def returnVPCSwitchHandle(log,vpc_switches):
    vpc_handle={}
    for x in vpc_switches:
        hdl = vpc_switches[x]
        cfg = 'show vpc role | xml'
        out = hdl.execute(cfg)
        log.info('The value of out is : {0}'.format(out))
        if out:
            s = BeautifulSoup(out)
            vpc_role = s.find('vpc-current-role').string
            log.info('The value of vpc_role is : {0}'.format(vpc_role))
            if '-' in vpc_role:
                b = vpc_role.split('-')
                log.info('The Value of b is : {0}'.format(b))
                if b[0] == 'primary':
                    vpc_handle.setdefault('secondary',{})
                    vpc_handle['secondary']['dut'] = x
                    vpc_handle['secondary']['hdl'] = hdl
                else:
                    vpc_handle.setdefault('primary',{})
                    vpc_handle['primary']['dut'] = x
                    vpc_handle['primary']['hdl'] = hdl
            elif 'primary' in vpc_role:
                vpc_handle.setdefault('primary',{})
                vpc_handle['primary']['dut'] = x
                vpc_handle['primary']['hdl'] = hdl
            elif 'secondary' in vpc_role:
                vpc_handle.setdefault('secondary',{})
                vpc_handle['secondary']['dut'] = x
                vpc_handle['secondary']['hdl'] = hdl
    
    log.info(banner('The Value of vpc_handle is {0}'.format(vpc_handle)))
    
    return vpc_handle

def parseScaleVlanParms(log,args):
    """Method to configure config under vpc domain"""
    log.info('Inside the parseScaleVlanParms function()')
    arggrammar = {}
    arggrammar['no_of_l2_vlans'] = '-type int'
    arggrammar['l2_vlan_start'] = '-type int'
    arggrammar['l2_vni_start'] = '-type int'
    arggrammar['no_of_l3_vlans'] = '-type int'
    arggrammar['l3_vlan_start'] = '-type int'
    arggrammar['l3_vni_start'] = '-type int'
    arggrammar['l2_vlan_name'] = '-type str'
    arggrammar['l2_vlan_shutdown'] = '-type bool -default False'
    arggrammar['l3_vlan_name'] = '-type str'
    arggrammar['l3_vlan_shutdown'] = '-type bool -default False'
    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def nveInterfaceMemberVniConfigUnconfig(log,hdl,configdict,mode):
    ns = parseScaleVlanParms(log,configdict)
    log.info('the value of ns is : {0}'.format(ns))
    if ns.l2_vni_start and mode == 'Config':
        for j in range(ns.l2_vni_start,ns.l2_vni_start+ns.no_of_l2_vlans):
            cfg = '''interface nve 1
                     member vni {0}
                     ingress-replication protocol bgp'''.format(j)
            hdl.configure(cfg)
    elif ns.l2_vni_start and mode == 'UnConfig':
        for j in range(ns.l2_vni_start,ns.l2_vni_start+ns.no_of_l2_vlans):
            cfg = '''interface nve 1
                     no member vni {0}'''.format(j)
            hdl.configure(cfg)

def getTrafficItemStatisticsIdeal(log,tgn_hdl,traffic_stream_dict,trf_item,threshold):
    log.info('Inside getTrafficItemStatistics')
    stream_name = traffic_stream_dict[trf_item]['stream_id']
    log.info(banner('The value of stream_name is : {0}'.format(stream_name)))
#    log.info(banner('The Value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
    stats = tgn_hdl.traffic_stats(stream = stream_name, mode = 'traffic_item')
    #log.info(banner('The Value of stats is : {0}'.format(stats)))
    tx_stat = stats.traffic_item[stream_name]['tx'].total_pkt_rate
    rx_stat = stats.traffic_item[stream_name]['rx'].total_pkt_rate
    if re.search('TRF|TEST|BL',trf_item):
        try:
            if not abs(rx_stat-tx_stat) <=threshold:
                log.error(banner('Traffic condition did not pass on the stream {0} before start of the test '.format(stream_name)))
                log.error(banner('The Value of Tx and Rx on Stream {0} are {1} and {2}'.format(stream_name,rx_stat,tx_stat)))
                return 0
            else:
                log.info(banner('Traffic flow is as expected on Stream {0}. Tx is : {1} and Rx is : {2}'.format(trf_item,tx_stat,rx_stat)))
                return 1
        except:
            log.info(banner('Traffic stats was not proper.. Waiting for 10 seconds before collecting it Again'))
            time.sleep(10)
            stats = tgn_hdl.traffic_stats(stream = stream_name, mode = 'traffic_item')
            tx_stat = stats.traffic_item[stream_name]['tx'].total_pkt_rate
            rx_stat = stats.traffic_item[stream_name]['rx'].total_pkt_rate
            if not abs(rx_stat-tx_stat) <= threshold:
                log.error(banner('Traffic condition did not pass on the stream {0} before start of the test '.format(stream_name)))
                log.error(banner('The Value of Tx and Rx on Stream {0} are {1} and {2}'.format(stream_name,rx_stat,tx_stat)))
                return 0
            else:
                log.info(banner('Traffic flow is as expected on Stream {0}. Tx is : {1} and Rx is : {2}'.format(trf_item,tx_stat,rx_stat)))
                return 1
            
    if re.search('RAW', trf_item):
        dst_ports_len = len(traffic_stream_dict[trf_item]['destination'])
        log.info('The value if dst_port_length is : {0}'.format(dst_ports_len))
        if not abs(rx_stat-dst_ports_len*tx_stat) <=threshold:
            log.error(banner('Traffic condition did not pass on the stream {0} before start of the test '.format(stream_name)))
            return 0
        else:
            log.info(banner('Traffic flow is as expected on Stream {0}. Tx is : {1} and Rx is : {2}'.format(trf_item,tx_stat,rx_stat)))
            return 1

def getRawTrafficItemStatisticsTrigger(log,tgn_hdl,traffic_stream_dict,trf_item,threshold,dev_len,trigger_type,no_of_vlan,*args):
    log.info('Inside getTrafficItemStatistics')
    stream_name = traffic_stream_dict[trf_item]['stream_id']
    log.info(banner('The value of stream_name is : {0}'.format(stream_name)))
#    log.info(banner('The Value of traffic_stream_dict is : {0}'.format(traffic_stream_dict)))
    stats = tgn_hdl.traffic_stats(stream = stream_name, mode = 'traffic_item')
    log.info(banner('The Value of stats is : {0}'.format(stats)))
    tx_stat = stats.traffic_item[stream_name]['tx'].total_pkt_rate
    rx_stat = stats.traffic_item[stream_name]['rx'].total_pkt_rate
    dst_ports_len = len(traffic_stream_dict[trf_item]['destination'])
    log.info('The value if dst_port_length is : {0}'.format(dst_ports_len))
    log.info('The value of intf_len is : {0}'.format(dev_len))
    if args:
        allowed_vlan = args
        log.info('The Value of allowed_Vlan inside getRawTrafficItemStatisticsTrigger is : {0}'.format(allowed_vlan))
    if trigger_type == 'access_port':
        exp_trf = (dst_ports_len - dev_len) * tx_stat + (tx_stat/no_of_vlan) * dev_len
        log.info('The value of exp_traffic is : {0}'.format(exp_trf))
        if not abs(rx_stat-exp_trf) <=threshold:
            log.error(banner('Traffic condition did not pass on the stream {0} before start of the test. Tx is {1} and Exp Rx is : {3} Actual Rx is : {2} '.format(trf_item,tx_stat,rx_stat,exp_trf)))
            return 0
        else:
            log.info(banner('Traffic flow is as expected on Stream {0}. Tx is : {1} and Exp Rx: {3} Actual Rx is : {2}'.format(trf_item,tx_stat,rx_stat,exp_trf)))
            return 1        
    if trigger_type == 'trunk_port_allowed_vlan':
        log.info('Insise trunk_port_allowed_vlan trigger')
        log.info('Value of allowed_Vlan is  : {0}'.format(allowed_vlan))
        for item in allowed_vlan:
            if isinstance(item, list):
                length_of_allowed_vlan_list = len(item) 
        log.info('The value of length_of_allowed_vlan_list is : {0}'.format(length_of_allowed_vlan_list))
        exp_trf = (dst_ports_len - dev_len) * tx_stat + (tx_stat/no_of_vlan) * length_of_allowed_vlan_list * dev_len
        log.info('The value of exp_traffic is : {0}'.format(exp_trf))
        if not abs(rx_stat-exp_trf) <=threshold:
            log.error(banner('Traffic condition did not pass on the stream {0} before start of the test. Tx is {1} and Exp Rx is : {3} Actual Rx is : {2} '.format(trf_item,tx_stat,rx_stat,exp_trf)))
            return 0
        else:
            log.info(banner('Traffic flow is as expected on Stream {0}. Tx is : {1} and Exp Rx: {3} Actual Rx is : {2}'.format(trf_item,tx_stat,rx_stat,exp_trf)))
            return 1
    if trigger_type == 'access_vpc_port' or 'access_vpc_port_shut':
        log.info('Insise access_vpc_port trigger')
        exp_trf = (dst_ports_len - dev_len) * tx_stat + (tx_stat/no_of_vlan) * dev_len
        log.info('The value of exp_traffic is : {0}'.format(exp_trf))
        if not abs(rx_stat-exp_trf) <=threshold:
            log.error(banner('Traffic condition did not pass on the stream {0} before start of the test. Tx is {1} and Exp Rx is : {3} Actual Rx is : {2} '.format(trf_item,tx_stat,rx_stat,exp_trf)))
            return 0
        else:
            log.info(banner('Traffic flow is as expected on Stream {0}. Tx is : {1} and Exp Rx: {3} Actual Rx is : {2}'.format(trf_item,tx_stat,rx_stat,exp_trf)))
            return 1        

    if trigger_type == 'trunk_vpc_port' or 'trunk_vpc_port_shut':
        log.info('Insise trunk_vpc_port trigger')
        exp_trf = (dst_ports_len - dev_len) * tx_stat + (tx_stat/no_of_vlan) * dev_len
        log.info('The value of exp_traffic is : {0}'.format(exp_trf))
        if not abs(rx_stat-exp_trf) <=threshold:
            log.error(banner('Traffic condition did not pass on the stream {0} before start of the test. Tx is {1} and Exp Rx is : {3} Actual Rx is : {2} '.format(trf_item,tx_stat,rx_stat,exp_trf)))
            return 0
        else:
            log.info(banner('Traffic flow is as expected on Stream {0}. Tx is : {1} and Exp Rx: {3} Actual Rx is : {2}'.format(trf_item,tx_stat,rx_stat,exp_trf)))
            return 1       


def cfgIntfSwtichPortMode(log,hdl,intf,mode,vlan,*args):
    log.info('Inside the cfgIntfSwtichPortMode')
    log.info('The value of intf is : {0}'.format(intf))
    log.info('The value of mode is : {0}'.format(mode))
    log.info('The value of vlan is : {0}'.format(vlan))
    if mode == 'access':
        cfg = '''default interface {0}
                 interface {0}              
                 switchport
                 switchport mode access
                 switchport access vlan {1}
                 spanning-tree port type edge
                 load-interval counter 1 5
                 load-interval counter 2 10
                 load-interval counter 3 15
                 no shutdown '''.format(intf,vlan)
        if args:
            cfg += '\n' + 'channel-group {0} force mode active'.format(args[0])
    elif mode == 'trunk':
        if isinstance(vlan, list):
            vlan = ",".join(str(x) for x in vlan)                   
        cfg = '''default interface {0}
                 interface {0}              
                 switchport
                 switchport mode trunk
                 switchport trunk allowed vlan {1}
                 spanning-tree port type edge trunk
                 load-interval counter 1 5
                 load-interval counter 2 10
                 load-interval counter 3 15
                 no shutdown '''.format(intf,vlan)
    hdl.configure(cfg)

    return 1


def randomIntgen(list_size, start, end):
    return [random.randint(start,end) for _ in range(0,list_size)]


def configBackUpOrRestoreOrCleanUp(log,hdl,mode):
    delete_cmd = 'delete bootflash:automation* no-prompt'
    store_cmd = 'copy running-config bootflash:automation_script_config'
    restore_cmd = 'configure replace bootflash:automation_script_config verbose'
    
    if mode == 'backup':
        hdl.execute(delete_cmd, timeout = 600)
        hdl.execute(store_cmd, timeout = 600)
    if mode == 'restore':
        hdl.execute(restore_cmd, timeout = 600)
    if mode == 'cleanup':
        hdl.execute(delete_cmd, timeout = 600)
    
    return 1

def parseVPCPortChannelParams(log,args):
    log.info('Inside the parseVPCPortChannelParams function()')
    arggrammar={}
    arggrammar['members'] = '-type str'
    arggrammar['pc_no'] = '-type str'
    arggrammar['vpc_id'] = '-type str'
    arggrammar['port_mode'] = '-type str'
    
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns

def Test():
    print('hi')
    
def flapInterface(log,hdl,intf,dut,t=5):
    log.info('Inside Flap Interface section')
    log.info(banner('Shuting down the interface {0} on dut {1}'.format(intf,dut)))
    cfg1 = '''interface {0}
             shutdown'''.format(intf)
    hdl.configure(cfg1, timeout = 600)
    log.info('sleepting for {2} seconds before unshutting the interface {0} on dut {1}'.format(intf,dut,t))
    time.sleep(t)
    cfg2 = '''interface {0}
             no shutdown'''.format(intf)
    hdl.configure(cfg2, timeout = 600)
    return 1

def shutDownInterface(log,hdl,intf,dut):
    log.info('Inside Shutdown Interface section')
    log.info(banner('shutting down the interface {0} on dut {1}'.format(intf,dut)))
    cfg1 = '''interface {0}
             shutdown'''.format(intf)
    hdl.configure(cfg1)
    return 1

def unshutDownInterface(log,hdl,intf,dut):
    log.info('Inside UnShutdown Interface section')
    log.info(banner('Unshutting  the interface {0} on dut {1}'.format(intf,dut)))
    cfg1 = '''interface {0}
             no shutdown'''.format(intf)
    hdl.configure(cfg1)
    return 1

def shutDownSVIInterface(log,hdl,dut,svi):
    log.info('Inside SVI shutdown Interface section')
    log.info(banner('Shutting down the interface Vlan {0} on dut {1}'.format(svi,dut)))
    intf = lambda svi : 'vlan' + str(svi)
    cfg = '''interface {0}
             shutdown'''.format(intf(svi))
    hdl.configure(cfg)
    return 1

def unShutDownSVIInterface(log,hdl,dut,svi):
    log.info('Inside SVI shutdown Interface section')
    log.info(banner('Shutting down the interface Vlan {0} on dut {1}'.format(svi,dut)))
    intf = lambda svi : 'vlan' + str(svi)
    cfg = '''interface {0}
             no shutdown'''.format(intf(svi))
    hdl.configure(cfg)
    return 1

def vlanOperations(log,hdl,dut,vlan,operation,vni=''):
    log.info("inside Vlan OPeration()")
    
    log.info(banner('Operation: {2} on Vlan {0} on dut {1}'.format(vlan, dut, operation)))
    if operation == 'shut':
        cfg = '''vlan {0}
                 shutdown'''.format(vlan)
    if operation == 'unshut':
        cfg = '''vlan {0}
                 no shutdown'''.format(vlan)
                 
    if operation == 'remove':
        cfg = 'no vlan {0}'.format(vlan)
        
    if operation == 'vni_change':
        cfg = '''vlan {0}
                 no vn-segment
                 vn-segment {1}'''.format(vlan,vni)
    hdl.configure(cfg)
    return 1

def sviOperations(log,hdl,dut,svi,operation):
    log.info('Inside SVI operations')
    if operation == 'delete':
        log.info('Deleting the SVI {0} on dut {1}'.format(svi,dut))
        cfg = 'no interface vlan {0}'.format(svi)
    hdl.configure(cfg)
    
def deleteScriptBackUpFiles(log,hdl):
    log.info('Deleting the already stored files before taking a backup')
    cfg = 'delete bootflash:script_use* no-prompt'
    hdl.execute(cfg)
    return 1


def vrfOperations(log,hdl,dut,vrf,operation):
    log.info("inside VRF OPeration()")
    
    log.info(banner('Shutting / Deleteingthe VRF {0} on dut {1}'.format(vrf, dut)))
    if operation == 'shut':
        cfg = '''vrf context {0}
                 shutdown'''.format(vrf)
    if operation == 'unshut':
        cfg = '''vrf context {0}
                 no shutdown'''.format(vrf)
    if operation == 'delete':
        log.info('Deleting the VRF {0} on dut {1}'.format(vrf,dut))
        cfg = 'no vrf context {0}'.format(vrf)
    hdl.configure(cfg)
    return 1


def verifyProcessRestart(log,dut, p_name):
    
    log.info('Inside verifyProcessRestart .....')
#     unicon_state = unicon.statemachine.statemachine.State(name='enable', pattern=r'^.*|%N#')
#     unicon_state.add_state_pattern(pattern_list = "r'bash-*$'")
    
    dut.configure("feature bash-shell")
    dut.configure('system no hap-reset')
    
    # Get the PID of the process before killing it
    pid_data = dut.execute("show system internal sysmgr service name " + str(p_name) + " | i i PID")
    pid_regex = re.search("PID = (\\d+)",pid_data,re.I)
    if pid_regex is not 0:
        pid = pid_regex.group(1)
    
    # Kill the process in bash prompt
    dut.execute("run bash", allow_state_change = "True")
    dut.execute("sudo su", allow_state_change = "True")
    dut.execute("kill -9 "+str(pid), allow_state_change = "True")
    dut.execute("exit", allow_state_change = "True")
    dut.execute("exit", allow_state_change = "True")
    
#     unicon_state.restore_state_pattern()
#     unicon_state = ""
    
    time.sleep(30)
    
    # Get the PID of the process after killing it
    post_kill_pid_data = dut.execute("show system internal sysmgr service name " + str(p_name) + " | i i PID")
    post_kill_pid_regex = re.search("PID = (\\d+)",post_kill_pid_data,re.I)
    if post_kill_pid_regex is not 0:
        post_kill_pid = post_kill_pid_regex.group(1)
    
    # Check if pre-kill PID and post-kill PID are different
    if pid != post_kill_pid:
        return 1
    else:
        return 0


def configureGlobalVxlanParams(dut,hdl,config_dict,log):
    ns = parseGlobalVxlanConfigs(log,config_dict) 
    cfg = ''
    if hasattr(ns, 'anycast_gateway_mac') and ns.anycast_gateway_mac:
        cfg += 'fabric forwarding anycast-gateway-mac 0000.1234.5678'   
    hdl.configure(cfg)
    return 1


def generateVRFlist(vrf_name,no):
    return [vrf_name.split('-')[0] + '-' + str("{:03d}".format(int(vrf_name.split('-')[-1])+i)) for i in range(no)]
    
def parseGlobalBGPconfigs(log, args):
    arggrammar = {}
    arggrammar['no_of_vrf'] = '-type int'
    arggrammar['vrf_start'] = '-type str'
    arggrammar['af_v4_enable'] = '-type str'
    arggrammar['af_v6_enable'] = '-type str'
    arggrammar['advertise_l2vpn_evpn'] = '-type bool'
    arggrammar['max_path_ebgp'] = '-type int'
    arggrammar['max_path_ibgp'] = '-type int'
    ns = utils.parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    return ns 

def configureGlobalBGPParams(dut,hdl,config_dict,log,as_no):
    ns = parseGlobalBGPconfigs(log,config_dict)

    if hasattr(ns,'vrf_start') and ns.vrf_start:
        vrf_name_list = generateVRFlist(ns.vrf_start,ns.no_of_vrf)
        log.info('the value of vrf_name_list is : {0}'.format(vrf_name_list))
    for i in range(0,ns.no_of_vrf):
        cfg = ''
        cfg += '''router bgp {0}
                  vrf {1}'''.format(as_no,vrf_name_list[i]) + '\n'
        if hasattr(ns, 'af_v4_enable') and ns.af_v4_enable:
            cfg += 'address-family ipv4 unicast' + '\n'
            if hasattr(ns, 'advertise_l2vpn_evpn') and ns.advertise_l2vpn_evpn:
                cfg += 'advertise l2vpn evpn' + '\n'
                if hasattr(ns, 'max_path_ebgp') and ns.max_path_ebgp:
                    cfg += 'maximum-paths {0}'.format(ns.max_path_ebgp) + '\n'
                if hasattr(ns, 'max_path_ibgp') and ns.max_path_ibgp:
                     cfg += 'maximum-paths ibgp {0}'.format(ns.max_path_ebgp) + '\n'
        if hasattr(ns, 'af_v6_enable') and ns.af_v6_enable:
            cfg += 'address-family ipv6 unicast' + '\n'
            if hasattr(ns, 'advertise_l2vpn_evpn') and ns.advertise_l2vpn_evpn:
                cfg += 'advertise l2vpn evpn' + '\n'
                if hasattr(ns, 'max_path_ebgp') and ns.max_path_ebgp:
                    cfg += 'maximum-paths {0}'.format(ns.max_path_ebgp) + '\n'
                if hasattr(ns, 'max_path_ibgp') and ns.max_path_ibgp:
                     cfg += 'maximum-paths ibgp {0}'.format(ns.max_path_ebgp) + '\n'  
        hdl.configure(cfg)
    
    return 1  
