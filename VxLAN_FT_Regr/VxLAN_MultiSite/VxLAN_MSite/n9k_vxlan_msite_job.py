from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    tmp_path = os.path.dirname(os.path.abspath(__file__))
    test_path = tmp_path.split('/')
    test_path.pop()
    test_path.append('scripts')
    test_path.append('n9k_msite_vpc_anycast.py')
    testscript = '/'.join(test_path)
    # run api launches a testscript as an individual task.
    run(testscript)
     #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupTgen'))
    # to run specific testcase
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupTgen','MSITE-FUNC-047','MSITE-FUNC-048','MSITE-FUNC-049','MSITE-FUNC-050','MSITE-FUNC-051','MSITE-FUNC-052','MSITE-FUNC-053','MSITE-FUNC-054','MSITE-FUNC-055','MSITE-FUNC-056','MSITE-FUNC-057','MSITE-FUNC-058','MSITE-FUNC-059','MSITE-FUNC-060','MSITE-FUNC-063','MSITE-FUNC-064','MSITE-FUNC-065','MSITE-FUNC-066','MSITE-FUNC-067','MSITE-FUNC-068','MSITE-FUNC-069','MSITE-FUNC-070','MSITE-FUNC-071','MSITE-FUNC-072','MSITE-FUNC-073','MSITE-FUNC-074','MSITE-FUNC-075','MSITE-FUNC-076','MSITE-FUNC-077','MSITE-FUNC-078','MSITE-FUNC-079','MSITE-FUNC-080','MSITE-FUNC-081','MSITE-FUNC-082','MSITE-FUNC-083','MSITE-FUNC-084','MSITE-FUNC-085','MSITE-FUNC-086','MSITE-FUNC-087','MSITE-FUNC-088','MSITE-FUNC-089','MSITE-FUNC-090','MSITE-FUNC-091','MSITE-FUNC-092','MSITE-FUNC-093','MSITE-FUNC-094','MSITE-FUNC-095','MSITE-FUNC-096','MSITE-FUNC-097'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupTgen','MSITE-FUNC-061'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupTgen','MSITE-FUNC-063','MSITE-FUNC-064','MSITE-FUNC-065','MSITE-FUNC-066','MSITE-FUNC-067','MSITE-FUNC-068','MSITE-FUNC-069','MSITE-FUNC-070','MSITE-FUNC-071','MSITE-FUNC-072','MSITE-FUNC-073','MSITE-FUNC-074','MSITE-FUNC-075','MSITE-FUNC-076','MSITE-FUNC-077','MSITE-FUNC-078','MSITE-FUNC-079','MSITE-FUNC-080','MSITE-FUNC-081','MSITE-FUNC-082','MSITE-FUNC-083','MSITE-FUNC-084','MSITE-FUNC-085','MSITE-FUNC-086','MSITE-FUNC-087','MSITE-FUNC-088','MSITE-FUNC-089','MSITE-FUNC-090','MSITE-FUNC-091','MSITE-FUNC-092','MSITE-FUNC-093','MSITE-FUNC-094','MSITE-FUNC-095','MSITE-FUNC-096','MSITE-FUNC-097'))
 
