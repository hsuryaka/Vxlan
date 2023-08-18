# To run the job:
# easypy basic_job.py -testbed_file basic_topo.yaml
#            
# Description: This example uses a sample testbed, connects to a device and ixia
#              details about the device and ixia are passed from the job file,
#              it has 4 testcase:
#
# TC01 => about running traffic and using ixia APIs
# TC02 => testcase to use ping and regexp
# TC03 => using router_show in python
# TC04 => using send and transmit to router in python

import os
from ats.easypy import run
# import the logic objects
from ats.datastructures.logic import And, Or, Not

#-----Test scale numbers----

 

def main():
    global uutList	
    test_path = os.path.dirname(os.path.abspath(__file__))
    #testscript = os.path.join(test_path, 'vxlan_evpn1.py')
    testscript = os.path.join(test_path, 'vxlan_evpn_ngpf_traffic_profile.py')


# # RUN all TC
    #run(testscript=testscript, uids=Not('TC044_vxlan_Z_Flow1','TC045_vxlan_Z_Flow2','CFD_CSCvr58479_IP_MAC_routes_in_BGP_after_SVI_removed'))
    #run(testscript=testscript, uids=Or('common_setup', Or('^TC001_.*', '^TC002_.*', '^TC003_.*', '^TC004_.*', '^TC05_.*')))
    run(testscript=testscript, uids=Or('common_setup', \
    Or('^TC001_.*', '^TC002_.*', '^TC003_.*', '^TC004_.*', '^TC05_.*','^TC0[3-4]_.*'),\
    Not('TC044_vxlan_Z_Flow1','TC045_vxlan_Z_Flow2','CFD_CSCvr58479_IP_MAC_routes_in_BGP_after_SVI_removed')))
    #run(testscript=testscript, uids=Or('common_setup', Or('^TC05_.*','^TC031_.*'),'common_cleanup'))
    
# # # RUN single TC
    # run(testscript=testscript,ids=Or('common_setup','TC01','common_cleanup'))
    
# # # Run multiple selected TC
    # run(testscript=testscript,ids=Or('common_setup',Or('^TC01.*','^TC02.*'),'common_cleanup'))
    
# # # Skip single TC
    # run(testscript=testscript,ids=Or('common_setup',Not('^TC02.*'),'common_cleanup'))
    
# # # Skip multiple TC
    # run(testscript=testscript,ids=Or('common_setup',Not('^TC02.*','^TC01.*'),'common_cleanup'))
  

 
