from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    tmp_path = os.path.dirname(os.path.abspath(__file__))
    test_path = tmp_path.split('/')
    test_path.pop()
    test_path.append('scripts')
    test_path.append('n9k_msite_trm.py')
    testscript = '/'.join(test_path)
    # run api launches a testscript as an individual task.
    #run(testscript)
    # to run specific testcase
    #run(testscript,uids =Or('common_setup'))
    run(testscript,uids =Or('common_setup','setupConfigVxlan'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupTgen','MSITE-TRM-FUNC-054'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupTgen','MSITE-TRM-FUNC-062','MSITE-TRM-FUNC-063','MSITE-TRM-FUNC-064','MSITE-TRM-FUNC-065','MSITE-TRM-FUNC-066','MSITE-TRM-FUNC-067','MSITE-TRM-FUNC-068','MSITE-TRM-FUNC-069','MSITE-TRM-FUNC-070','MSITE-TRM-FUNC-071','MSITE-TRM-FUNC-072','MSITE-TRM-FUNC-073','MSITE-TRM-FUNC-074','MSITE-TRM-FUNC-075','MSITE-TRM-FUNC-076','MSITE-TRM-FUNC-077','MSITE-TRM-FUNC-078','MSITE-TRM-FUNC-079','MSITE-TRM-FUNC-080','MSITE-TRM-FUNC-081','MSITE-TRM-FUNC-082','MSITE-TRM-FUNC-083'))
