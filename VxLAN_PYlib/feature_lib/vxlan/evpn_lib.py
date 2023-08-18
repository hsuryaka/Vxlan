
import os
import sys

from feature_lib.vxlan import evpn_lib
from common_lib import parserutils_lib
from common_lib import utils
#from pkgIndex_lib import *


class configEvpn():

    def __init__(self,dut,hdl,config_dict,log):

        self.log = log
        self.hdl = hdl
        self.configSuccess = 1

        self.log.info('Enabling nv overlay evpn on the switch')
        hdl.configure('nv overlay evpn')
            
        for vni in config_dict['vni'].keys():
            obj = evpn_lib.configEvpnVni(vni,dut,hdl,log,config_dict['vni'][vni])
            if obj.configSuccess == 0:
                self.log.info('Error: calling configEvpnVni')
                self.configSuccess = 0
                break
        return

class configEvpnVni():

    def __init__(self,vni,dut,hdl,log,args):

        self.log = log
        self.hdl = hdl
        self.configSuccess = 1

        arggrammar={}
        arggrammar['layer']='-type str -default NULL'
        arggrammar['rd']='-type str -default NULL'
        arggrammar['route_target_import_list']='-type str -default NULL'
        arggrammar['route_target_export_list']='-type str -default NULL'
        try:
            ns=parserutils_lib.argsToCommandOptions(args,arggrammar,self.log)
        except Exception as e:
            log.error('Args parsing failed for evpn')
            #return 0
 
        layer    = ns.layer
        rd       = ns.rd
        rtilist  = ns.route_target_import_list
        rtxlist  = ns.route_target_export_list

        cmd = ""
        cmd += 'evpn\r'
        cmd += 'vni {0} {1}\r'.format(vni,layer)
        if rd != 'NULL':
            cmd += 'rd {0}\r'.format(rd)
        if rtilist != 'NULL':
            for rti in utils.strToList(rtilist):
                cmd += 'route-target import {0}\r'.format(rti)
        if rtxlist != 'NULL':
            for rtx in utils.strToList(rtxlist):
                cmd += 'route-target export {0}\r'.format(rtx)
        
        self.log.info('Configuring vni {0} on {1}'.format(vni,dut))
        hdl.configure(cmd)

def setupConfigEvpn(hdl,dut,log,config_dict):
                ''' method to configure EVPN dict defined for each dut under topology'''
                if 'evpn_config_dict' in config_dict:
                    if dut in config_dict['evpn_config_dict']:
                        obj_evpn=evpn_lib.configEvpn(dut,hdl,config_dict['evpn_config_dict'][dut],log)
                        if not obj_evpn.configSuccess:
                                return 0
                return 1

# Parsers 
def getL2evpnSummaryDict(hdl,log,*args):

    '''Returns l2 evpn summary o/p in the below form:
    l2evpn:
        neighbors:
            31.1.1.0:
                version: 4
                as: 65000
                up_down_status: 3d01h
                prefix_rvd: 23
            31.1.2.0:
                version: 4
                as: 65000
                up_down_status: 3d01h
                prefix_rvd: 23
    '''
    arggrammar={}
    arggrammar['vrf']='-type str -default default'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    neighbor_pat='([0-9\.]+)\s+([0-9]+)\s+([0-9]+)\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+([0-9a-zA-Z\:]+)\s+([0-9a-zA-Z]+)'

    op=hdl.iexec('show bgp l2vpn evpn summary vrf {0}'.format(ns.vrf))
    neighbor_pat_match=re.findall(neighbor_pat,op)

    l2evpn_dict = {}
    l2evpn_dict['l2evpn'] = {}
    l2evpn_dict['l2evpn']['neighbors'] = {}
    for val in neighbor_pat_match:
        #l2evpn_dict['l2evpn']['neighbors'] = val[0]
        l2evpn_dict['l2evpn']['neighbors'][val[0]] = {}
        l2evpn_dict['l2evpn']['neighbors'][val[0]]['version'] = val[1]
        l2evpn_dict['l2evpn']['neighbors'][val[0]]['as'] = val[2]
        l2evpn_dict['l2evpn']['neighbors'][val[0]]['up_down_status'] = val[3]
        l2evpn_dict['l2evpn']['neighbors'][val[0]]['prefix_rvd'] = val[4]
    return l2evpn_dict


def getL2evpnRouteDict(hdl,log,*args):

    '''returns l2 evpn advertised-routes or received-routes o/p in the below form:
    l2evpn:
        rd:
            65:10:
                1:
                    mac: 0011.0100.0001
                    ip:  0.0.0.0
                    nexthop: 1.1.1.0
                2:
                    mac: 0011.0100.0001
                    ip:  0.0.0.0
                    nexthop: 1.1.1.0
    '''
    arggrammar={}
    arggrammar['vrf']='-type str -default default'
    arggrammar['neighbor']='-type str -default None'
    arggrammar['direction']='-type str -default advertised'
    ns=parserutils_lib.argsToCommandOptions(args,arggrammar,log)
    rd_pat='Route Distinguisher:'
    rd1_pat='^\s+([0-9\:\.]+)'
    info_pat='([0-9a-fA-F\.]+)\]\:\[[0-9]+\]\:\[([0-9\.:a-fA-F]+)\]/[0-9]+\s*\n\s*([0-9\.]+)'

    if re.match( 'advertised', ns.direction, flags=re.I ):
        dir = 'advertised-routes'
    elif re.match( 'received', ns.direction, flags=re.I ):
        dir = 'received-routes'
    else:
        self.log.error('direction parameter can be only advertised or received')
        return 0

    if ns.neighbor is None:
        self.log.error('neighbor parameter is mandatory for getL2evpnAdvertisedRouteDict')
        return 0

    op=hdl.iexec('show bgp l2vpn evpn neighbors {0} {1} vrf {2}'.format(ns.neighbor,dir,ns.vrf))
    rd_breakup = re.split(rd_pat,op)
    
    l2evpn_dict = {}
    l2evpn_dict['l2evpn'] = {}
    l2evpn_dict['l2evpn']['rd'] = {}
    for each_rd_sec in rd_breakup:
        rd = re.match(rd1_pat,each_rd_sec)
        if rd != None:
            l2evpn_dict['l2evpn']['rd'][rd.group(1)] = {}
            routes_info = re.findall(info_pat,each_rd_sec)
            itr = 1
            for val in routes_info:
                l2evpn_dict['l2evpn']['rd'][rd.group(1)][itr] = {}
                l2evpn_dict['l2evpn']['rd'][rd.group(1)][itr]['mac'] = val[0]
                l2evpn_dict['l2evpn']['rd'][rd.group(1)][itr]['nexthop'] = val[1]
                l2evpn_dict['l2evpn']['rd'][rd.group(1)][itr]['ip'] = val[2]
                itr = itr+1
           
    return l2evpn_dict

