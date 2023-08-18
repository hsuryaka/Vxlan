# To run the job:
# easypy otm.py -testbed_file ../inputs/device.yaml --testcase_file ../inputs/testcase.yaml
# testbed_file: Standard pyATS testbed file.
# testcase_file: Custom testcase input file.
# namespace: Uses the namespace - http://www.cisco.com/yang/nxos-dev/top
#     This namespace is deprecated from freeport (N9K)
#     If you want to use new namespace - http://cisco.com/ns/yang/cisco-nx-os-device, please exit and use job file otm_new_ns.py instead

import os
import argparse

from ats.easypy import run

# All run() must be inside a main function
def main():
    # Find the location of the script in relation to the job file
    test_path = (os.path.dirname(os.path.abspath(__file__)).replace('/jobs', '/tests'))
    testscript = os.path.join(test_path, 'otm.py')

    parser = argparse.ArgumentParser()
    parser.add_argument('--testcase_file', help='file specifying the test cases', default = None)

    args = parser.parse_args()

    # Execute the testscript
    run(testscript=testscript, testcase_file = args.testcase_file, namespace="old")
