from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    tmp_path = os.path.dirname(os.path.abspath(__file__))
    #test_path = tmp_path.split('/')
    #test_path.pop()
    #test_path.append('scripts')
    #test_path.append('n39k_vxlan_oam_script.py')
    testscript = './TOR/n39k_vxlan_oam_script.py'
    # run api launches a testscript as an individual task.
    run(testscript)
    # to run specific testcase
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','VXLAN-OAM-FUNC-006'))
    #run(testscript,uids =Or('common_setup','VXLAN-OAM-FUNC-026'))
    #run(testscript,uids =Or('common_setup'))
