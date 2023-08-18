from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    tmp_path = os.path.dirname(os.path.abspath(__file__))
    test_path = tmp_path.split('/')
    test_path.pop()
    test_path.append('scripts')
    test_path.append('n9k_vmct_pvmap.py')
    testscript = '/'.join(test_path)
    # run api launches a testscript as an individual task.
    run(testscript)
    # to run specific testcase
    #run(testscript,uids =Or('common_setup','setupTgen','VMCT-PMAP-FUNC-001'))
