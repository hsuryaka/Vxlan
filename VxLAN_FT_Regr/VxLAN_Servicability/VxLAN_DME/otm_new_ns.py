# To run the job:
# easypy otm_new_ns.py -testbed_file ../inputs/device.yaml --testcase_file ../inputs/testcase.yaml
# testbed_file: Standard pyATS testbed file.
# testcase_file: Custom testcase input file.
# This file uses new namespace - http://cisco.com/ns/yang/cisco-nx-os-device

import os
import argparse

from ats.datastructures.logic import Or
from ats.easypy import run

# All run() must be inside a main function
def main():
    # Find the location of the script in relation to the job file
    test_path = (os.path.dirname(os.path.abspath(__file__)).replace('/jobs', '/tests'))
    testscript = os.path.join(test_path, 'otm.py')

    # If user wants RPM installation and removal
    test_path = (os.path.dirname(os.path.abspath(__file__)).replace('/jobs', '/tests/utils'))
    rpm_testscript = os.path.join(test_path, 'rpm_utils.py')

    parser = argparse.ArgumentParser()
    parser.add_argument('--testcase_file', help='file specifying the test cases', default = None)
    parser.add_argument('--upg_img', help='Provide full path to the upgrade or downgrade image or both in order separated by comma', default = None)
    parser.add_argument('--rpmfileloc', help='Provide the directory where rpm files are located', default=None)
    parser.add_argument('--rpms', help='Provide the list of RPMS to be installed', default=None)
    parser.add_argument('--include_list', help='Provide the traffic item list to be included', default=None)
    parser.add_argument('--exclude_list', help='Provide the traffic item list to be excluded', default=None)
    parser.add_argument('--pkt_threshold', help='Provide the packet threshold', default=0)
    parser.add_argument('--skip_traffic', help='Specify True to skip traffic, default is False', default=False)
    args = parser.parse_args()

    # RPM installation args
    _rpmfile_location = str(args.rpmfileloc)
    _rpm_list = str(args.rpms)
    if ',' in _rpm_list:
        _rpmlist = _rpm_list.split(',')
    else:
        _rpmlist = _rpm_list.split()

    # Image for ISSU/ISSD Trigger args
    _upg_img = args.upg_img
    if _upg_img is None: _upg_img = os.environ.get('UPG_IMG')

    # Traffic args
    _inc_list = args.include_list
    _exc_list = args.exclude_list
    _pkt_threshold = args.pkt_threshold
    _skip_traffic = args.skip_traffic
    _inc_list = [x.strip() for x in _inc_list.split(',')] if _inc_list else []
    _exc_list = [x.strip() for x in _exc_list.split(',')] if _exc_list else []

    # Execute the rpm installation
    if args.rpmfileloc is not None:
        run(testscript=rpm_testscript, rpmfileloc=_rpmfile_location, rpmlist=_rpmlist,
            uids = Or('common_setup','oc_rpm_install','common_cleanup'))

    # Execute the testscript
    run(testscript=testscript, testcase_file = args.testcase_file, namespace="new", upgimg = _upg_img,
        inc_list=_inc_list, exc_list=_exc_list, pkt_threshold=_pkt_threshold, skip_traffic=_skip_traffic)

    # Execute the rpm un-installation
    if args.rpmfileloc is not None:
        run(testscript=rpm_testscript, rpmfileloc=_rpmfile_location, rpmlist=_rpmlist,
            uids = Or('common_setup','oc_rpm_uninstall','common_cleanup'))

