
import os
import sys
import utils
import bringup_lib
#import parserutils_lib


## Will be expanded with detailed verification later ..

def configPrefixLists(log, switch_hdl_dict, prefix_list_config_dict):
    try:
       list_of_nodes=switch_hdl_dict.keys()
    except KeyError:
       err_msg='Error !!! prefix_list_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
       log.error(err_msg)

    for node in list_of_nodes:
        hdl=switch_hdl_dict[node]
        prefix_lists=prefix_list_config_dict[node].keys()

        for prefix_list in prefix_lists:
            #cfg='no ip prefix-list {0}'.format(prefix_list)
            #hdl.configure(cfg)
            raw_configs=prefix_list_config_dict[node][prefix_list]
            cfg=raw_configs.replace("\\" , "\r")
            cfg=cfg.replace("\"" , "")
            hdl.configure(cfg)
            #if hdl.errFlag:
            #       log.error('Configuring Prefix or Community List has failed for {0}'.format(hdl.switchName))
            #       return 0
    return 1


def unconfigPrefixLists(log, switch_hdl_dict, prefix_list_config_dict):
    try:
       list_of_nodes=switch_hdl_dict.keys()
    except KeyError:
       err_msg='Error !!! prefix_list_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
       log.error(err_msg)

    for node in list_of_nodes:
        hdl=switch_hdl_dict[node]
        prefix_lists=prefix_list_config_dict[node].keys()

        for prefix_list in prefix_lists:
            cfg='no ip prefix-list {0}'.format(prefix_list)
            hdl.configure(cfg)
    return 1


def configRouteMaps(log, switch_hdl_dict, route_map_config_dict):
    try:
       list_of_nodes=switch_hdl_dict.keys()
    except KeyError:
       err_msg='Error !!! route_map_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
       log.error(err_msg)
    for node in list_of_nodes:
        hdl=switch_hdl_dict[node]
        route_maps=route_map_config_dict[node].keys()

        for route_map in route_maps:
            raw_configs=route_map_config_dict[node][route_map]
            cfg=raw_configs.replace("\\" , "\r")
            cfg=cfg.replace("\"" , "")
            hdl.configure(cfg)
    return 1
 

def unconfigRouteMaps(log, switch_hdl_dict, route_map_config_dict):
    try:
       list_of_nodes=switch_hdl_dict.keys()
    except KeyError:
       err_msg='Error !!! route_map_config_dict has not been defined properly, does not have nodes   \
              as the top level keys'
       log.error(err_msg)

    for node in list_of_nodes:
        hdl=switch_hdl_dict[node]
        route_maps=route_map_config_dict[node].keys()

        for route_map in route_maps:
            cfg='no route-map {0}'.format(route_map)
            hdl.configure(cfg)
    return 1
 
