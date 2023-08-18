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
    print(' testpath',test_path)
    testscript = os.path.join(test_path, 'multisitesa.py')
    #testbed = os.path.join(test_path, testbed_file)
    print(' testscript',testscript)
    #print(' testbed',testbed)


# # RUN all TC
    run(testscript=testscript)

 
