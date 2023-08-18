
# This file contains the global variables, this needs to be imported in all files where these variables are used

import os

TB        = {}
GLOBAL    = {}

GLOBAL['run_id_file']        = '/auto/bgl-golden/var/runinfo/run_id'

if os.environ.get('HLITELOGS'):
    GLOBAL['logdir']=os.environ['HLITELOGS']
else:
    GLOBAL['logdir']="/tmp"
