#!/usr/bin/env python
import re
import pdb
import logging
import time
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

def FloodTrafficGeneratorScale(port_handle,vlan,ip_sa,ip_da,rate_pps,count):
    
    log.info(banner('in FloodTrafficGeneratorScale '))
    
    str1=hex(randint(16,54))[2:]
    str2=hex(randint(55,104))[2:]
    str3=hex(randint(32,80))[2:]
    str4=hex(randint(50,95))[2:]
    
    mac1='00:'+str4+':'+str2+':'+str1+':'+str3+':02'
    
    device_ret = ixiangpf.traffic_config (
        mode            =       'create',
        traffic_generator  =    'ixnetwork_540',
        emulation_src_handle  =  port_handle,
        l2_encap        =       'ethernet_ii_vlan',
        vlan_id         =       vlan,
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
        transmit_mode   =       'continuous')
    