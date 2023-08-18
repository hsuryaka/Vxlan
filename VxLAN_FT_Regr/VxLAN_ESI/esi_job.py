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
    testscript = './3esi.py'
 


# # RUN all TC
    run(testscript=testscript)
    
# # # RUN single TC
    # run(testscript=testscript,ids=Or('common_setup','TC01','common_cleanup'))
    
# # # Run multiple selected TC
    # run(testscript=testscript,ids=Or('common_setup',Or('^TC01.*','^TC02.*'),'common_cleanup'))
    
# # # Skip single TC
    # run(testscript=testscript,ids=Or('common_setup',Not('^TC02.*'),'common_cleanup'))
    
# # # Skip multiple TC
    # run(testscript=testscript,ids=Or('common_setup',Not('^TC02.*','^TC01.*'),'common_cleanup'))
  

 
