import os

import logging
import argparse

from ats.easypy import run

parser = argparse.ArgumentParser()

parser.add_argument('--build',
                    help='image build to be tested',
                    default = None)


# Compute relative location of this file
HERE = os.path.dirname(__file__)

def main(runtime):
    # main entry point for a job is the main() function
    # args, unknown = parser.parse_known_args()

    custom_args = parser.parse_known_args()[0]

    # find our abspath to the script
    script = os.path.join(HERE, 'Project_Script.py')

    # run this script as a task under this job
    # Note:
    #   if --testbed-file is provided, the corresponding loaded 'testbed'
    #   object will be provided to each script within this job automatically
    # runtime.tasks.run(script) 
 
    run(testscript=script,runtime = runtime,**vars(custom_args))