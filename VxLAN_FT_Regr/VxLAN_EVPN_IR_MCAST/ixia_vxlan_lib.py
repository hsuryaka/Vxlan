#!/usr/bin/env python
import re
import pdb
import logging
import time
from randmac import RandMac
#import pexpect
from time import sleep
import threading
import hashlib
import sys
from ipaddress import *
import json
from ats.log.utils import banner
from random import *
from ats.topology import Device
import requests
from ats import aetest, log
from ats.log.utils import banner
from netaddr import *
from re import *
from vxlan_all_lib1 import *

#from randmac import RandMac
from unicon.utils import Utils
import socket
from pyats.async_ import pcall
from unicon.eal.dialogs import Statement, Dialog
from unicon.utils import Utils
import collections

#### sep 19
from genie.libs.conf.interface.nxos import Interface
from genie.libs.conf.ospf.nxos.ospf import Ospf
#from genie.libs.conf.rip.rip import Rip
#pkgs/conf-pkg/src/genie/libs/conf/ospf/nxos/ospf.py

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


#import general_lib
#ixia source 
from ixiatcl import IxiaTcl
from ixiahlt import IxiaHlt
from ixiangpf import IxiaNgpf
from ixiaerror import IxiaError

 
ixiatcl = IxiaTcl()
ixiahlt = IxiaHlt(ixiatcl)
#if the user wishes to set HLTSET at instantiation : ixiahlt = IxiaHlt(ixiatcl, ixia_version='HLTSET166')
ixiangpf = IxiaNgpf(ixiahlt)
 


#ixiahlt.connect(device = str('10.127.63.100'),reset=1,port_list = port_list,ixnetwork_tcl_server= '10.104.104.243',break_locks = 1)
#       _result_ = ixiangpf.connect(
#            device                  = args_dict['chassis_ip'],
#            port_list               = args_dict['port_list'],
#            ixnetwork_tcl_server    = ixTclServer,
#            reset                   = args_dict['reset'],
#            ,
#            break_locks             = 1
#        )



def ixia_connect(labserver_ip,tgn_ip,port_list):    
    ixia_tcl_server_addr_str = str(labserver_ip) + ":" + str(8009)
    _result_ = ixiahlt.connect(
                                device = str(tgn_ip),
                                reset=1,
                                port_list = port_list,
                                ixnetwork_tcl_server= ixia_tcl_server_addr_str,
                                break_locks = 1
                                    )
    if _result_['status'] == '1':
        #print("Ixia connection successfull")
        log.info("Ixia Connection is Successfull")
        return _result_
    else:
        #print("Ixia Connection Failed")
        log.info("Ixia connection id Failed")
        return 0
        



#RESET ALL
#ixiahlt.traffic_config(port_handle=port_handle_list, mode='reset',)


def ixia_flood_traffic_config(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    log.info(banner('in ixia_flood_traffic_config '))
    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]

    mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
    #mac2='00:10:'+str1+':'+str2+':'+str4+':02'

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator = 'ixnetwork_540',
        port_handle     =       port_handle,
        l2_encap        =      'ethernet_ii_vlan',
        vlan_id         =       vlan,
        vlan            =       "enable",
        stream_id       =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        mac_dst         =       'ff:ff:ff:ff:ff:ff',
        mac_src         =       mac1,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)
    
    print("Flood_traffic", device_ret)

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** run ixiahlt.traffic_config successfully")
        return 1


def ixia_unicast_bidir_traffic_config(port_hdl1,port_hdl2,vlan1,vlan2,scale,ip1,ip2,gw1,gw2,rate_pps):
    #log.info(banner("------SpirentHostBidirStream-----"))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,vlan1,vlan2,scale,ip1,ip2,gw1,gw2)


    mac1 = str(RandMac("00:00:00:00:00:00", True)).replace("'","")
    mac2 = str(RandMac("00:00:00:00:00:00", True)).replace("'","")


    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator =    'ixnetwork_540',
        port_handle     =       port_hdl1,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan            =       "enable",
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip1,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       scale,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip2,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       scale,
        ip_dst_mode     =       'increment',
        mac_src         =       mac1,
        mac_dst         =       mac2,
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)
    #print("Bidir Stream 222", device_ret)
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl1 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl1 ixiahlt.traffic_config successfully")        


    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator =    'ixnetwork_540',
        port_handle     =       port_hdl2,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan2,
        vlan            =       "enable",
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip2,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       scale,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip1,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       scale,
        ip_dst_mode     =       'increment',
        mac_src         =       mac2,
        mac_dst         =       mac1,
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)
    #print("Bidir Stream 222", device_ret)
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl1 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl2 ixiahlt.traffic_config successfully")  

    return 1          




def ixia_routed_bidir_traffic_config(uut,port_hdl1,port_hdl2,pps):
    log.info(banner("------ixia_routed_bidir_traffic_config-----"))

    pps = 2*pps

    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'MS-IR' in line:
                vrf = line.split()[-2].replace("[","").replace("]","")
                vrf_list.append(vrf)
            else:    
                vrf = line.split()[-1].replace("[","").replace("]","")
                vrf_list.append(vrf)


    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        vlan_list.append(line.split()[0].replace("Vlan",""))
                        ip_list.append(line.split()[1])

        if not len(vlan_list) == len(ip_list):
            return 0
        else:
            gw1 = str(ip_address(ip_list[0]))
            ip1 = str(ip_address(gw1)+1)
            ip11= str(ip_address(ip1)+100)

            ixis_host_bidir_stream_smac_same(port_hdl1,port_hdl2,vlan_list[0],vlan_list[0],ip1,ip11,ip11,ip1,str(pps))

            for i in range(1,len(vlan_list)):
                vlan2 = vlan_list[i]
                gw2 = ip_list[i]
                ip2 = str(ip_address(gw2)+100)
                ixis_host_bidir_stream_smac_same(port_hdl1,port_hdl2,vlan_list[0],vlan2,ip1,ip2,gw1,gw2,str(pps))

    return 1




def ixia_v6_unicast_bidir_stream(port_hdl1,port_hdl2,vlan1,vlan2,scale,ipv61,ipv62,rate_pps):
    log.info(banner("STARTING SpirentV6BidirStream "))
    log.info('VLAN1 : %r,VLAN2 : %r,SCALE : %r,IP1 : %r,IP2 : %r ' ,vlan1,vlan2,scale,ipv61,ipv62)

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl1,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan1,
        vlan            =       "enable",
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv6',
        ipv6_src_addr   =       ipv61,
        ipv6_src_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_src_count  =       scale,
        ipv6_src_mode   =       'increment',
        ipv6_dst_addr   =       ipv62,
        ipv6_dst_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_dst_count  =       scale,
        ipv6_dst_mode   =       'increment',
        mac_src         =       '00:12:60:60:00:02',
        mac_dst         =       '00:13:60:60:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl1 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl1 ixiahlt.traffic_config successfully")
        
        

    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_hdl2,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan2,
        vlan            =       "enable",
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv6',
        ipv6_src_addr   =       ipv62,
        ipv6_src_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_src_count  =       scale,
        ipv6_src_mode   =       'increment',
        ipv6_dst_addr   =       ipv61,
        ipv6_dst_step   =       '0000:0000:0000:0000:0000:0000:0001:0000',
        ipv6_dst_count  =       scale,
        ipv6_dst_mode   =       'increment',
        mac_src         =       '00:13:60:60:00:02',
        mac_dst         =       '00:12:60:60:00:02',
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        mac_src_step    =       '00:00:00:00:00:01',
        mac_dst_count   =       scale,
        mac_dst_mode    =       'increment',
        mac_dst_step    =       '00:00:00:00:00:01',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)
    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl2 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl2 ixiahlt.traffic_config successfully")





def ixis_host_bidir_stream_smac_same(port_hdl1,port_hdl2,vlan1,vlan2,ip1,ip2,gw1,gw2,rate_pps):
    log.info(banner("------ixis_host_bidir_stream_smac_same-----"))

    str11 = hex(int(vlan1))[2:][:2]
    str12 = hex(int(vlan1))[2:][1:]
    str21 = hex(int(vlan2))[2:][:2]
    str22 = hex(int(vlan2))[2:][1:]

    if vlan1==vlan2:
        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:11:'+str22+':'+str22+':'+str21+':44'
    else:
        mac1='00:10:'+str11+':'+str12+':'+str11+':22'
        mac2='00:10:'+str21+':'+str22+':'+str21+':22'

    #print("port_hdl1", port_hdl1)
    log.info('IP1 : %r,IP2 : %r GW1 :%r GW2 :%r' ,ip1,ip2,gw1,gw2)
    device_ret1 =ixiahlt.interface_config (mode = 'config',\
    port_handle = port_hdl1,vlan = 1, vlan_id  = vlan1,intf_ip_addr = ip1, netmask = '255.255.0.0',\
    gateway = gw1,src_mac_addr = mac1)
    
    #print("port_hdl1 status", device_ret1)
    
    if device_ret1['status'] == '1':
        log.info('Successfully configured protocol interfaces')
    else:
        log.error('Failed to configure protocol interfaces')
    
    #print("port_hdl2", port_hdl2)
    device_ret2 =ixiahlt.interface_config (mode = 'config',port_handle = port_hdl2,\
    vlan = 1, vlan_id  = vlan2, intf_ip_addr = ip2, netmask = '255.255.0.0',\
    gateway = gw2, src_mac_addr = mac2)
    
    #print("port_hdl2 status",device_ret2)
    
    if device_ret2['status'] == '1':
        log.info('Successfully configured protocol interfaces')
    else:
        log.error('Failed to configure protocol interfaces')
        
    #print("device_ret1 value is",device_ret1)
    #print("device_ret2 value is",device_ret2)
    h1 = device_ret1['interface_handle']
    h2 = device_ret2['interface_handle']

    streamblock_ret1 = ixiahlt.traffic_config (mode= 'create',port_handle= port_hdl1,\
    emulation_src_handle=h1,emulation_dst_handle = h2,bidirectional='1',\
    port_handle2=port_hdl2,transmit_mode='continuous',rate_pps=rate_pps,length_mode ='auto',track_by ='trackingenabled0',)
    
    status = streamblock_ret1['status']

    log.info('+-----------------------------------------------------------------------+')
    log.info('stream_id : %r, vlan1 : %r ,vlan2 : %r ,rate_pps : %r',streamblock_ret1['stream_id'],vlan1,vlan2,rate_pps)
    log.info('IP1 : %r,IP2 : %r, Host1 : %r ,Host2 : %r ',ip1,ip2,h1,h2)
    log.info('+-----------------------------------------------------------------------+')
    if (status == '0') :
        log.info('run ixiahlt.traffic_config failed for V4 %r', streamblock_ret1)
    else:
        log.info('***** run ixiahlt.traffic_config successful for V4')



def ixia_vxlan_traffic_test(port_handle1,port_handle2,rate,pps,orphan_handle_list):
    rate3=893700
    diff = int(rate3*.0350)
    test1=ixia_rate_test(port_handle1,port_handle2,rate3,diff)

    if not test1:
        log.info(banner("Rate test Failed"))
        return 0
  
    for port_hdl in orphan_handle_list:
        if port_hdl:
            try:            
                res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')
                #print('traffic_status of res', res)
            except:
                log.info('Stats failed for port %r',port_hdl)
                return 0
            try:               
                rx_rate = int(res['aggregate']['rx']['raw_pkt_rate']['max'])
                #rx_rate = res['item0']['PortRxTotalFrameRate']
            except:
                log.info('rx_rate failed for port %r',port_hdl)
                return 0

            log.info('+------------------Traffic test at orphan ports------------------------+')
            log.info('+---- Actual RX rate at Port %r is : %r ------+',port_hdl,rx_rate)
            log.info('+---- Expected RX rate at Port %r is : %r ------+',port_hdl,800000)
            log.info('+----------------------------------------------------------------------+')
            if abs(int(rx_rate) - 800000) > diff:
                log.info('Traffic  Rate Test failed for %r',port_hdl)
                log.info('Stats are %r',res)
                return 0
            
    return 1


def ixia_rate_test(port_hdl1,port_hdl2,rate_fps,diff):
    log.info(banner("  Starting ixia_rate_test "))
    diff = 4*int(diff)
    rate_fps =  893700
    result = 1
    for port_hdl in [port_hdl1,port_hdl2]:
        log.info("port_hdl %r,rate_fps %r,diff is %r", port_hdl,rate_fps,diff)
        try:            
            res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')
            #print('traffic_status of res', res)
        except:
            log.info('Stats failed for port %r',port_hdl)
            return 0
        try:               
            rx_rate = int(res['aggregate']['rx']['raw_pkt_rate']['max'])
            #tx_rate = int(res['aggregate']['tx']['total_pkt_rate']['max'])
        except:
            log.info('rx_rate failed for port %r',port_hdl)
            return 0
        log.info('+-----------------------------------------------------------------------+')
        log.info('rx_rate is %r,exp_rate is %r',rx_rate,rate_fps)
        log.info('+-----------------------------------------------------------------------+')
        #if abs(int(rx_rate) - int(tx_rate)) > diff:
        #    log.info('Traffic  Rate Test failed - TX / RX difference is %r',abs(int(rx_rate) - int(tx_rate)))
        #    #log.info('Streamblock is %r',res)
        #    result = 0
        if abs(int(rx_rate) - int(rate_fps)) > diff:
            log.info('Traffic  Rate Test failed, Rate & FPS diff is %r',abs(int(rx_rate) - int(rate_fps)))
            #log.info('Streamblock is %r',res)
            result = 0
    log.info(banner(" Completed Spirent Rate Test "))
    return result



def ixia_rate_test_all(port_hdl_list,rate_list):
    log.info(banner("  Starting ixia_rate_test "))

    result = 1
    for port_hdl,rate_fps in zip(port_hdl_list,rate_list):
        diff = int(rate_fps*.0350)
        log.info("port_hdl %r,rate_fps %r,diff is %r", port_hdl,rate_fps,diff)
        try:            
            res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')
        except:
            log.info('Stats failed for port %r',port_hdl)
            return 0
        try:               
            rx_rate = int(res['aggregate']['rx']['raw_pkt_rate']['max'])
        except:
            log.info('rx_rate failed for port %r',port_hdl)
            return 0
        log.info('+-----------------------------------------------------------------------+')
        log.info('rx_rate is %r,exp_rate is %r',rx_rate,rate_fps)
        log.info('+-----------------------------------------------------------------------+')
  
        if abs(int(rx_rate) - int(rate_fps)) > diff:
            log.info('Traffic  Rate Test failed, Rate & FPS diff is %r',abs(int(rx_rate) - int(rate_fps)))
            result = 0
    log.info(banner(" Completed Spirent Rate Test "))
    return result



def rate_test_ixia(port_hdl,exp_rate):
    log.info(banner('Start rate_test'))
    diff = int(exp_rate*.065)  
    i = 1
    while True:    
        try:            
            #res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')

            # log.info("====>")
            # print(res)
            # log.info(res)
            # log.info("====>")

        except:
            log.error('Stats failed for port %r',port_hdl)
            return 0
        try:               
            #rx_rate = res['item0']['PortRxTotalFrameRate']

            rx_rate = int(res['aggregate']['rx']['raw_pkt_rate']['max'])

            log.info('+-------------------------------------------------------------------------+')
            log.info('+ + + + + Port:%r,diff: %r,RX:%r, Exp: %r + + + + + ',port_hdl,diff,rx_rate,exp_rate)
            log.info('+-------------------------------------------------------------------------+')
        except:
            log.error('rx_rate failed for port %r',port_hdl)
            return 0
        if abs(int(rx_rate) - int(exp_rate)) < diff:         
            log.info('Passed rateTest for port %r, Time is  %r , breaking loop',port_hdl,i)
            break
        countdown (10)
        i += 1
        log.info('repeating test @ port %r , Time elapsed ++ %r',port_hdl,int(i)*10)
        if i > 30:
            log.info("rate_test completed for 300 Seconds, Test FAIL")
            return 0            
    return 1


def rate_test_nil_ixia(port_hdl):
    log.info(banner('Start rate_test_nil'))
    i = 1
    while True:    
        try:            
            #res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')
        except:
            log.error('Stats failed for port %r',port_hdl)
            return 0
        try:               
            rx_rate = int(res['aggregate']['rx']['raw_pkt_rate']['max'])
            log.info('+-------------------------------------------------------------------------+')
            log.info('+ + + + + Port:%r ,RX:%r, + + + + + ',port_hdl,rx_rate)
            log.info('+-------------------------------------------------------------------------+')
        except:
            log.error('rx_rate errored for port %r',port_hdl)
            return 0

        if int(rx_rate) < 5:         
            log.info('Passed rateTest for port %r, Time is  %r , breaking loop',port_hdl,i)
            break
        countdown (10)
        i += 1

        log.info('repeating test @ port %r , Time elapsed ++ %r',port_hdl,int(i)*10)
        if i > 5:
            log.info("rate_test completed for 300 Seconds, Test FAIL")
            return 0            
    return 1



def traffic_test_ixia(port_handle_list,rate_list):
    for port_hdl,exp_rate in zip(port_handle_list,rate_list):
        if not rate_test_ixia(port_hdl,exp_rate):
            log.info('rate_test failed for  %r',port_hdl)
            return 0
        else:
            log.info('traffictest1 PASSED for port @1 %r',port_hdl)

    log.info('traffictest1 PASSED for ports %r',port_handle_list)        
    return 1


def traffic_test_ixia_sa_remove(port_handle_list,rate_list):
    for port_hdl,exp_rate in zip(port_handle_list,rate_list):
        if not rate_test_ixia_sa_remove(port_hdl,exp_rate):
            log.info('rate_test failed for  %r',port_hdl)
            return 0
        else:
            log.info('traffictest1 PASSED for port @1 %r',port_hdl)

    log.info('traffictest1 PASSED for ports %r',port_handle_list)        
    return 1

def rate_test_ixia_sa_remove(port_hdl,exp_rate):
    log.info(banner('Start rate_test'))
    diff = int(exp_rate*.365)  
    i = 1
    while True:    
        try:            
            #res = sth.drv_stats(query_from = port_hdl,properties = "Port.TxTotalFrameRate Port.RxTotalFrameRate")
            res = ixiahlt.traffic_stats(port_handle = port_hdl,mode = 'aggregate',traffic_generator = 'ixnetwork')

        except:
            log.error('Stats failed for port %r',port_hdl)
            return 0
        try:               
            #rx_rate = res['item0']['PortRxTotalFrameRate']

            rx_rate = int(res['aggregate']['rx']['raw_pkt_rate']['max'])

            log.info('+-------------------------------------------------------------------------+')
            log.info('+ + + + + Port:%r,diff: %r,RX:%r, Exp: %r + + + + + ',port_hdl,diff,rx_rate,exp_rate)
            log.info('+-------------------------------------------------------------------------+')
        except:
            log.error('rx_rate failed for port %r',port_hdl)
            return 0
        if abs(int(rx_rate) - int(exp_rate)) < diff:         
            log.info('Passed rateTest for port %r, Time is  %r , breaking loop',port_hdl,i)
            break
        countdown (10)
        i += 1
        log.info('repeating test @ port %r , Time elapsed ++ %r',port_hdl,int(i)*10)
        if i > 30:
            log.info("rate_test completed for 300 Seconds, Test FAIL")
            return 0            
    return 1

def ixia_arp_suppression_test_OLD(port_handle_list,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):
    log.info(banner("Starting VxlanStArpGen"))

    #for port_hdl in  port_handle_list:
    #    log.info("Resetting all Streams for Port %r",port_hdl)
    #    traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'reset' ,db_file=0 )

    ip_sa1 = ip_address(ip_sa)
    ip_da1 = ip_address(ip_da)
    mac_sa1 = EUI(mac_sa)

    for port_hdl in  port_handle_list:
        #log.info("Adding ARP Stream for Port %r",port_hdl)
        ixia_arp_traffic_generate(port_hdl,vlan,str(ip_sa1),str(ip_da1),str(mac_sa1),rate_pps,count)
        mac_sa2 = int(mac_sa1)+1
        mac_sa1 = EUI(mac_sa2)
        ip_sa1 =  ip_sa1+1
        ip_da1 =  ip_da1

    for port_hdl in  port_handle_list:
        log.info("Starting ARP Stream Traffic for Port %r",port_hdl)
        traffic_ctrl_ret = sth.traffic_control(port_handle = port_hdl, action = 'run')

    log.info(banner("Starting ARP for all streams"))
    for i in range(1,4):
        doarp = sth.arp_control(arp_target='allstream',arpnd_report_retrieve='1')





def ixia_arp_suppression_test(vpc_uut_list,sa_leaf_uut_list,vlan_vni_scale,routing_vlan_scale,port_handle_sa,orphan_handle_list):
    log.info(banner("----VERIFY arp_suppression_test--"))
    fail_list = []
    for uut in vpc_uut_list:
        op1=uut.execute('show ip arp suppression-cache summary | json-pretty')
        op2=json.loads(op1)
        remote_arp_count = op2["TABLE_arp-suppression"]['ROW_arp-suppression']['TABLE_summary']['ROW_summary']['remote-count']
        if int(remote_arp_count) < int(vlan_vni_scale):
            fail_list.append('fail')

    for uut in sa_leaf_uut_list:
        op1=uut.execute('show ip arp suppression-cache summary | json-pretty')
        op2=json.loads(op1)
        remote_arp_count = op2["TABLE_arp-suppression"]['ROW_arp-suppression']['TABLE_summary']['ROW_summary']['remote-count']
        if int(remote_arp_count) < int(routing_vlan_scale):
            fail_list.append('fail')


    log.info(banner("Testing Traffic "))
    if not traffic_test_ixia([port_handle_sa],[int(vlan_vni_scale)*100]):
        fail_list.append('fail')

    for port_handle in orphan_handle_list:    
        if not rate_test_nil_ixia(port_handle):    
            fail_list.append('fail')

    if 'fail' in fail_list:
        return 0
    else:
        return 1  


def ixia_arp_request_config(uut,port_hdl1,port_hdl2,pps):
    log.info(banner("------ixia_routed_bidir_traffic_config-----"))
    op = uut.execute('show nve vni  | incl L3')
    op1 = op.splitlines()
    vrf_list=[]
    for line in op1:
        if line:
            if 'MS-IR' in line:
                vrf = line.split()[-2].replace("[","").replace("]","")
                vrf_list.append(vrf)
            else:    
                vrf = line.split()[-1].replace("[","").replace("]","")
                vrf_list.append(vrf)
    for vrf in vrf_list:
        op = uut.execute('show ip int brief vrf {vrf}'.format(vrf=vrf))
        op1 = op.splitlines()
        vlan_list = []
        ip_list = []
        for line in op1:
            if line:
                if 'Vlan' in line:
                    if not 'forward-enabled' in line:
                        vlan_list.append(line.split()[0].replace("Vlan",""))
                        ip_list.append(line.split()[1])

        if not len(vlan_list) == len(ip_list):
            return 0
        else:
            gw1 = str(ip_address(ip_list[0]))
            ip1 = str(ip_address(gw1)+1)
            ip11= str(ip_address(ip1)+100)
        for i in range(0,len(vlan_list)):
            vlan = vlan_list[i]
            gw = ip_list[i]
            ip_sa = str(ip_address(gw)+50)
            ip_da = str(ip_address(gw)+150)
            mac_sa =  str(RandMac("00:00:00:00:00:00", True)).replace("'","")
            ixia_arp_traffic_generate(port_hdl1,vlan,ip_sa,ip_da,mac_sa,1)


def ixia_arp_traffic_generate(port_handle,vlan,ip_sa,ip_da,mac_sa,rate_pps,count):

    log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    #streamblock_ret1 = sth.traffic_config (
    device_ret = ixiahlt.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        stream_id = vlan,
        vlan  =  "enable",
        vlan_id=vlan,
        l3_protocol = 'arp',
        ip_src_addr = ip_sa,
        ip_src_count = count,
        ip_src_mode = 'increment',
        ip_src_step ='0.0.0.1',
        ip_dst_addr = ip_da,
        ip_dst_count = count,
        ip_dst_mode = 'increment',
        ip_dst_step ='0.0.0.1',
        arp_src_hw_addr = mac_sa,
        arp_src_hw_mode = 'increment',
        arp_src_hw_count = count,
        arp_dst_hw_addr = "00:00:00:00:00:00",
        arp_dst_hw_mode = "fixed",
        arp_operation = "arpRequest",
        rate_pps = rate_pps,
        mac_src = mac_sa,
        mac_dst = 'ff:ff:ff:ff:ff:ff',
        mac_src_count= count,
        mac_src_mode='increment',
        mac_src_step='00:00:00:00:00:01',
        transmit_mode = 'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)

    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl2 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl2 ixiahlt.traffic_config successfully")




def arp_request_traffic_generate_ixia(port_handle,vlan,ip_da,rate_pps):
    log.info(banner("------in arp_request_traffic_generate-----"))
    vlan = str(vlan)
    ip_sa = str(ip_address(ip_da)-10)
    mac_sa =  str(RandMac("00:00:00:00:00:00", True)).replace("'","")
    #streamblock_ret1 = sth.traffic_config (

    _result_ = ixiahlt.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        stream_id       =       vlan,
        vlan_id=vlan,
        vlan  =  "enable",
        vlan_id_count=1,
        vlan_id_mode='increment',
        l3_protocol = 'arp',
        ip_src_addr = ip_sa,
        ip_src_count = 1,
        ip_src_mode = 'increment',
        ip_src_step ='0.1.0.0',
        ip_dst_addr = ip_da,
        ip_dst_count = 1,
        ip_dst_mode = 'increment',
        ip_dst_step ='0.1.0.0',
        arp_src_hw_addr = mac_sa,
        arp_src_hw_mode = 'increment',
        arp_src_hw_count = 1,
        arp_dst_hw_addr = "00:00:00:00:00:00",
        arp_dst_hw_mode = "fixed",
        arp_operation = "arpRequest",
        rate_pps = rate_pps,
        mac_src = mac_sa,
        mac_dst = 'ff:ff:ff:ff:ff:ff',
        mac_src_count= 1,
        mac_src_mode='increment',
        mac_src_step='00:00:00:00:00:01',
        transmit_mode = 'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)

    if _result_['status'] != IxiaHlt.SUCCESS:
        log.info("arp_request_traffic_generate_ixia failed")
        return 0
    else:
        log.info("arp_request_traffic_generate_ixia PASS")        
        return 1    



def ixia_arp_populate(port_handle,rate_pps,count):

    log.info("port_handle %r vlan %r ip_sa %r ip_da %r mac_sa %r ",port_handle,vlan,ip_sa,ip_da,mac_sa)
    #streamblock_ret1 = sth.traffic_config (


    mac_sa =  str(RandMac("00:00:00:00:00:00", True)).replace("'","")
    device_ret = ixiahlt.traffic_config (
        mode = 'create',
        port_handle = port_handle,
        l2_encap = 'ethernet_ii_vlan',
        stream_id = 1001,
        vlan  =  "enable",
        vlan_id=1001,
        vlan_id_count = count,
        vlan_id_mode = 'increment',
        l3_protocol = 'arp',
        ip_src_addr = "5.1.0.44",
        ip_src_count = count,
        ip_src_mode = 'increment',
        ip_src_step ='0.1.0.0',
        ip_dst_addr = "5.1.0.144",
        ip_dst_count = count,
        ip_dst_mode = 'increment',
        ip_dst_step ='0.0.0.1',
        arp_src_hw_addr = mac_sa,
        arp_src_hw_mode = 'increment',
        arp_src_hw_count = count,
        arp_dst_hw_addr = "00:00:00:00:00:11",
        arp_dst_hw_mode = "fixed",
        arp_operation = "arpRequest",
        rate_pps = rate_pps,
        mac_src = mac_sa,
        mac_dst = 'ff:ff:ff:ff:ff:ff',
        mac_src_count= count,
        mac_src_mode='increment',
        mac_src_step='00:00:00:00:00:11',
        transmit_mode = 'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)

    status = device_ret['status']
    if (status == '0'):
        log.info("port_hdl2 ixiahlt.traffic_config failed")
        return 0
    else:
        log.info("***** port_hdl2 ixiahlt.traffic_config successfully")






 
 
def arp_suppression_test_OLD(uut,port_handle):
    op1 = uut.execute("show ip arp suppression-cache remote")
    count = 0
    for line in op1.splitlines():
        if 'null' in line:
            ip_da = line.split()[0]
            ip_sa= str(ip_address(ip_da)+50)
            mac_da =  line.split()[2]
            vlan =  line.split()[3]
            mac_sa = str(RandMac("00:00:00:00:00:00", True)).replace("'","")  
            if count < 10:
                ixia_arp_traffic_generate(port_handle,vlan,ip_sa,ip_da,mac_sa,20000,1)
                count = count + 1

           
 
def arp_sa_test_vpc(vpc_uut_list,sa_leaf_uut_list,vlan_vni_scale,routing_vlan_scale,port_handle_sa,orphan_handle_list):
    log.info(banner("----VERIFY arp_sa_test--"))
    fail_list = []
    for uut in vpc_uut_list:
        op1=uut.execute('show ip arp suppression-cache summary | json-pretty')
        op2=json.loads(op1)
        remote_arp_count = op2["TABLE_arp-suppression"]['ROW_arp-suppression']['TABLE_summary']['ROW_summary']['remote-count']
        if int(remote_arp_count) < int(vlan_vni_scale):
            fail_list.append('fail')

    for uut in sa_leaf_uut_list:
        op1=uut.execute('show ip arp suppression-cache summary | json-pretty')
        op2=json.loads(op1)
        remote_arp_count = op2["TABLE_arp-suppression"]['ROW_arp-suppression']['TABLE_summary']['ROW_summary']['remote-count']
        if int(remote_arp_count) < int(routing_vlan_scale):
            fail_list.append('fail')


    log.info(banner("Testing Traffic "))
    if not traffic_test_ixia([port_handle_sa],[int(vlan_vni_scale)*100]):
        fail_list.append('fail')

    for port_handle in orphan_handle_list:    
        if not rate_test_nil_ixia(port_handle):    
            fail_list.append('fail')

    if 'fail' in fail_list:
        return 0
    else:
        return 1     


def arp_sa_test_standalone(vpc_uut_list,sa_leaf_uut_list,vlan_vni_scale,routing_vlan_scale,port_handle_sw,orphan_handle_list):
    log.info(banner("----VERIFY arp_sa_test--"))
    fail_list = []
    for uut in sa_leaf_uut_list:
        op1=uut.execute('show ip arp suppression-cache summary | json-pretty')
        op2=json.loads(op1)
        remote_arp_count = op2["TABLE_arp-suppression"]['ROW_arp-suppression']['TABLE_summary']['ROW_summary']['remote-count']
        if int(remote_arp_count) < int(vlan_vni_scale):
            fail_list.append('fail')

    for uut in vpc_uut_list:
        op1=uut.execute('show ip arp suppression-cache summary | json-pretty')
        op2=json.loads(op1)
        remote_arp_count = op2["TABLE_arp-suppression"]['ROW_arp-suppression']['TABLE_summary']['ROW_summary']['remote-count']
        if int(remote_arp_count) < int(routing_vlan_scale):
            fail_list.append('fail')


    log.info(banner("Testing Traffic "))
    if not traffic_test_ixia([port_handle_sw],[int(vlan_vni_scale)*100]):
        fail_list.append('fail')

    for port_handle in orphan_handle_list:    
        if not rate_test_nil_ixia(port_handle):    
            fail_list.append('fail')

    if 'fail' in fail_list:
        return 0
    else:
        return 1   



def arp_sa_reset_ixia(uut_list,port_handle_list):
    cfg_shut_noshut =  \
    """
    interface nve1
    shut
    sleep 4
    interface nve1
    no shut
    """
    try:
        for uut in uut_list:
            uut.configure(cfg_shut_noshut)
        countdown(10)
        for uut in uut_list:
            for i in range(1,4):
                uut.execute('clear mac address-table dynamic')
                uut.execute('clear ip arp vrf all')

        log.info(banner("ARP for all streams"))
        #for i in range(1,5):
        #    doarp = ixia.interface_config(arp_send_req='1',port_handle=port_handle_list)
        #    doarp = ixia.traffic_config(arp_send_req='1',arp_operation='arpRequest',port_handle=port_handle_list)

    except:
        log.error('SA reset fail')
        countdown(60)
        return 0
    countdown(60)    
    return 1


def ixia_igmp_host_control(port_handle_list,mode):
    # mode - join /leave/restart
    for port_handle in port_handle_list:
        start_igmp = ixia.emulation_igmp_control(
        port_handle = port_handle,
        mode = mode,
        )


def ixia_l2_mcast_traffic_configure(uut,port_hdl_src,mcast_address):
    log.info(banner("------l2_mcast_traffic_configure-----"))
    mcast_address1 = mcast_address
    op = uut.execute('show nve vni | inc L2')
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'nve1' in line:
                if 'L2' in line:
                    vlan = line.split()[6].replace("[","").replace("]","")
                    ip1 = find_svi_ip222(uut,vlan)
                    ip_sa1=str(ip_address(ip1)+10)
                    try:
                        log.info('Start ixia_mcast_traffic_create')
                        ixia_mcast_traffic_config(port_hdl_src,vlan,ip_sa1,mcast_address1,1000,1)
                    except:
                        log.error("ixia_mcast_traffic_create/l2_mcast_traffic_configure failed ")
                        return 0
                    mcast_address1 = str(ip_address(mcast_address1)+1)

    return 1


def ixia_l2_mcast_receiver_configure(uut,port_hdl_rcver_list,mcast_address):
    log.info(banner("------l2_mcast_receiver_confogure-----"))
    mcast_address1 = mcast_address
    op = uut.execute('show nve vni | inc L2')
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'nve1' in line:
                if 'L2' in line:
                    vlan = line.split()[6].replace("[","").replace("]","")
                    ip_sa1=str(ip_address(find_svi_ip222(uut,vlan))+10)
                    for port_handle in port_hdl_rcver_list:
                        host_ip= str(ip_address(ip_sa1)+randint(32001,64000))
                        log.info('host_ip is ------ %r',host_ip)
                        check11 = str(255)
                        if check11 in host_ip:
                            host_ip = str(ip_address(host_ip)+2)
                        log.info('---------vlan is %r-----------',vlan)
                        log.info('---------host_ip is %r-----------',host_ip)
                        log.info('---------mcast_address is %r-----------',mcast_address)
                        log.info('---------Going to ixia_igmp_host_create-----------')  
                        try:     
                            ixia_igmp_host_create(port_handle=port_handle,\
                                vlan = vlan,
                                vlan_scale = 1,
                                host_ip =host_ip,
                                mcast_group = mcast_address1,
                                mcast_group_scale = 1)
                        except:
                            log.error("l2_mcast_receiver_configure/ixia_igmp_host_create failed ")
                            return 0
                    
                    mcast_address1 = str(ip_address(mcast_address1)+1)

    return 1
 
#ixia_mcast_traffic_config(port_handle_sw1,1001,'5.1.1.22','239.1.1.1',10000,1)


def ixia_mcast_traffic_config(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    log.info(banner('+++ ixia_mcast_traffic_config +++ '))
    mac1 = str(RandMac("00:00:00:00:00:00", True))
    mac_sa = mac1.replace("'","")
    mac_da=ip2mac(ip_da) 

    log.info('mac_sa is %r',mac_sa)  
    log.info('mac_da is %r',mac_da)  
    log.info('vlan is %r',vlan)  
    log.info('ip_sa is %r',ip_sa)  
    log.info('ip_da is %r',ip_da)  
    log.info('rate_pps is %r',rate_pps)  
    log.info('count is %r',count)  

    
    device_ret = ixiahlt.traffic_config (mode='create',traffic_generator = 'ixnetwork_540',\
    port_handle=port_handle,l2_encap='ethernet_ii_vlan',stream_id=vlan,vlan_id =vlan,vlan="enable",vlan_id_count=count,\
    vlan_id_mode ='increment',l3_protocol='ipv4',ip_src_addr=ip_sa,ip_src_step='0.1.0.0',\
    ip_src_count =1,ip_src_mode='increment',ip_dst_addr=ip_da,mac_dst =mac_da,\
    mac_src =mac_sa,mac_src_count=1,mac_src_mode ='increment',rate_pps=rate_pps,transmit_mode='continuous',length_mode ='auto',track_by ='trackingenabled0',)

    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiahlt.traffic_config failed:  status == '0'")
        return 0
    else:
        log.info("***** run ixiahlt.traffic_config successfully")
        return 1



def ixia_mcast_traffic_config_OLD(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    log.info(banner('+++ ixia_mcast_traffic_config +++ '))
    mac1 = str(RandMac("00:00:00:00:00:00", True))
    mac_sa = mac1.replace("'","")
    mac_da=ip2mac(ip_da)  
    try:
        log.info('mac_sa is %r',mac_sa)  
        log.info('mac_da is %r',mac_da)  
        log.info('vlan is %r',vlan)  
        log.info('ip_sa is %r',ip_sa)  
        log.info('ip_da is %r',ip_da)  
        log.info('rate_pps is %r',rate_pps)  
        log.info('count is %r',count)  

        device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        traffic_generator =  'ixnetwork_540',
        port_handle     =    port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        stream_id       =       vlan,
        vlan            =       "enable",
        vlan_id         =       vlan,
        vlan_id_count   =       count,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       count,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       ip_da,
        mac_dst         =       mac_da,
        mac_src         =       mac1,
        mac_src_count   =       count,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)
    except:
        log.error('traffic_config exception')
        return 0
     
    status = device_ret['status']
    if (status == '0') :
        log.info("run ixiahlt.traffic_config failed:  status == '0'")
        return 0
    else:
        log.info("***** run ixiahlt.traffic_config successfully")
        return 1



def ixia_mcast_traffic_create(port_handle,vlan,ip_sa,mcast_address,rate_pps):
    log.info(banner('+++ ixia_mcast_traffic_create +++ '))
    mac_add1 = str(RandMac("00:00:00:00:00:00", True))
    mac_sa = mac_add1.replace("'","")
    mac_da=ip2mac(mcast_address)       
    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan,
        vlan            =       "enable",
        vlan_id_count   =       1,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       1,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       mcast_address,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       1,
        ip_dst_mode     =       'increment',
        mac_dst         =       mac_da,
        mac_dst_count   =       1,
        mac_dst_mode    =       'increment',
        mac_src         =       mac_sa,
        mac_src_count   =       1,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)

    status = device_ret['status']
    if (status == '0') :
        log.info("run sth.emulation_device_config failed")
        return 0
    else:
        log.info("***** run sth.emulation_device_config successfully")
        return 1

 


def ixia_mcast_traffic_create_scale(port_handle,vlan,ip_sa,mcast_address,rate_pps,scale):
    log.info(banner('+++ ixia_mcast_traffic_create_scale +++ '))
    mac_add1 = str(RandMac("00:00:00:00:00:00", True))
    mac_sa = mac_add1.replace("'","")
    mac_da=ip2mac(mcast_address)       
    device_ret = ixiahlt.traffic_config (
        mode            =       'create',
        port_handle     =       port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan,
        vlan            =       "enable",
        vlan_id_count   =       scale,
        vlan_id_mode    =       'increment',
        l3_protocol     =       'ipv4',
        ip_src_addr     =       ip_sa,
        ip_src_step     =       '0.1.0.0',
        ip_src_count    =       scale,
        ip_src_mode     =       'increment',
        ip_dst_addr     =       mcast_address,
        ip_dst_step     =       '0.1.0.0',
        ip_dst_count    =       1,
        ip_dst_mode     =       'increment',
        mac_dst         =       mac_da,
        mac_dst_count   =       1,
        mac_dst_mode    =       'increment',
        mac_src         =       mac_sa,
        mac_src_count   =       scale,
        mac_src_mode    =       'increment',
        rate_pps        =       rate_pps,
        transmit_mode   =       'continuous',
        length_mode='auto',
        track_by='trackingenabled0',)

    status = device_ret['status']
    if (status == '0') :
        log.info("run sth.ixia_mcast_traffic_create_scale failed")
        return 0
    else:
        log.info("***** run sth.emulation_device_config successfully")
        return 1



def ixia_igmp_host_create(port_handle,**kwargs):
    log.info(banner('IgmpHostCreate')) 
    #log.info('1111  kwargs are %r',kwargs)

    mcast_group_scale = 1  
    mcast_group = '239.1.1.1'
    #vlan = '1001'
    nei_ip = '5.1.0.2'
    vlan_scale = 1
    igmp_version = choice(['v3','v2'])
    
    for arg in kwargs:
        if 'igmp_version' in arg:
            igmp_version = kwargs['igmp_version']
        elif 'vlan' in arg:
            vlan = kwargs['vlan']
        elif 'nei_ip' in arg:
            nei_ip = kwargs['nei_ip']
        elif 'vlan_scale' in arg:
            vlan_scale = kwargs['vlan_scale']
        elif 'host_ip' in arg:
            host_ip = kwargs['host_ip']
        elif 'mcast_group' in arg:
            mcast_group = kwargs['mcast_group']
        elif 'mcast_group_scale' in arg:
            mcast_group_scale = kwargs['mcast_group_scale']
        elif 'ssm_source' in arg:
            ssm_source = kwargs['ssm_source']


    #log.info('2222 kwargs are %r',kwargs)
   
    log.info(banner('In ixia_igmp_host_create, Start emulation_multicast_group_config'))   
    #create_groups  = ixiahlt.emulation_multicast_group_config (
    #    mode = 'create',
    #    ip_prefix_len = '32',
    #    ip_addr_start = mcast_group,
    #    ip_addr_step = '1',
    #    num_groups = mcast_group_scale,
    #    pool_name = 'TRM')  

    create_groups  = ixiahlt.emulation_multicast_group_config (mode = 'create',\
        ip_addr_start = mcast_group,ip_addr_step = '0.0.0.1',num_groups = mcast_group_scale)  
 

    group_pool_name = create_groups['handle']
            
    log.info(banner('In ixia_igmp_host_create, Start emulation_igmp_config'))      
    if not 'Nil' in vlan:
        for vlan in range(int(vlan),int(vlan) + vlan_scale):
            mac_add1 = str(RandMac("00:00:00:00:00:00", True))
            mac1 = mac_add1.replace("'","")
            host_create = ixiahlt.emulation_igmp_config (
                mode = 'create',
                source_mac = mac1,
                igmp_version = igmp_version,
                port_handle = port_handle,
                ip_router_alert=1,
                count = 1,
                vlan_id=vlan,
                intf_ip_addr = host_ip,
                neighbor_intf_ip_addr = nei_ip,
                )
            host_ip = str(ip_address(host_ip)+65536)
            nei_ip = str(ip_address(nei_ip)+65536)

            if host_create['status']:
                log.info('IGMP Host created')
                host_handle = host_create['handle']
                device_ret0_group_config = ixiahlt.emulation_igmp_group_config (
                session_handle = host_handle,
                mode = 'create',
                group_pool_handle = group_pool_name,
                )
                if device_ret0_group_config['status']:
                    log.info('IGMP Host created , and group added')

    else:
        str4=hex(randint(16,54))[2:]
        str3=hex(randint(55,104))[2:]
        str2=hex(randint(32,80))[2:]
        str1=hex(randint(50,95))[2:]       
        mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
        log.info('igmp host SMAC : %r',mac1)   
        host_create = ixiahlt.emulation_igmp_config (
                mode = 'create',
                source_mac = mac1,
                igmp_version = igmp_version,
                port_handle = port_handle,
                ip_router_alert=1,
                count = 1,
                intf_ip_addr = host_ip,
                neighbor_intf_ip_addr = nei_ip,
                )
        host_ip = str(ip_address(host_ip)+65536)
        nei_ip = str(ip_address(nei_ip)+65536)

        if host_create['status']:
            log.info('IGMP Host created')
            host_handle = host_create['handle']
            device_ret0_group_config = ixiahlt.emulation_igmp_group_config (
                session_handle = host_handle,
                mode = 'create',
                group_pool_handle = group_pool_name,
                )
            if device_ret0_group_config['status']:
                log.info('IGMP Host created , and group added')



def l2_mcast_traffic_configure_ixia(uut,port_hdl_src,mcast_address):
    log.info(banner("------l2_mcast_traffic_configure_ixia-----"))
    mcast_address1 = mcast_address
    op = uut.execute('show nve vni | inc L2')
    op1 = op.splitlines()
    for line in op1:
        if line:
            if 'nve1' in line:
                if 'L2' in line:
                    vlan = line.split()[6].replace("[","").replace("]","")
                    ip1 = find_svi_ip222(uut,vlan)
                    ip_sa1=str(ip_address(ip1)+10)
                    try:
                        log.info('Start ixia_mcast_traffic_create')
                        ixia_mcast_traffic_create(port_hdl_src,vlan,ip_sa1,mcast_address1,1000)
                    except:
                        log.error("ixia_mcast_traffic_create failed ")
                        return 0
                    mcast_address1 = str(ip_address(mcast_address1)+1)

    return 1
