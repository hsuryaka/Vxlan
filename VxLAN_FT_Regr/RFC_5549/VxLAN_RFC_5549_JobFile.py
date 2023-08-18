##############
# HOW TO RUN #
##############
# bash-4.2$ cd /ws/jumashan-bgl/pyats_feb_2021/
# bash-4.2$ source env.sh
# (pyats_feb_2021) bash-4.2$ cd /ws/jumashan-bgl/pyats_new/
# (pyats_feb_2021) bash-4.2$ cd nxos/
# (pyats_feb_2021) bash-4.2$ source nxos-env.sh
# (pyats_feb_2021) bash-4.2$ source /auto/pysw/ats64/env.csh
# (pyats_feb_2021) bash-4.2$ cd /ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/RFC_5549
# (pyats_feb_2021) bash-4.2$ easypy VxLAN_RFC_5549_JobFile.py -testbed_file VxLAN_RFC_5549_TestBedFile.yaml


# EARMS from KR3F #128 : https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jumashan-bgl/pyats_feb_2021/users/jumashan/archive/22-03/VxLAN_RFC_5549_JobFile.2022Mar08_03:00:10.699440.zip&atstype=ATS
# EARMS from KR3F #128 : https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jumashan-bgl/pyats_feb_2021/users/jumashan/archive/22-03/VxLAN_RFC_5549_JobFile.2022Mar08_05:38:33.955929.zip&atstype=ATS
# EARMS from KR3F #135 : https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jumashan-bgl/pyats_feb_2021/users/jumashan/archive/22-03/VxLAN_RFC_5549_JobFile.2022Mar09_16:53:36.505977.zip&atstype=ATS

import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = os.path.join(test_path, '../MyScripts/RFC_5549/VxLAN_RFC_5549_ScriptFile.py')

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    uut_devices = {
        'Spine-01'          : 'Spine-01',
        'Sundown-01'        : 'Sundown-01',
        'Sundown-02'        : 'Sundown-02',
        'Sumpin-01'         : 'Sumpin-01',
        'NepCR-01'          : 'NepCR-01',
        'ixia'              : 'IXIA',
    }

    run(testscript=testscript, \
        uut_list=uut_devices, \
        uids = Or('common_setup', \
                'DEVICE_BRINGUP', \
                'IXIA_CONFIGURATION', \
                'TC000_Verify_Steady_State',\
                'TC001_SA_UP_Link_Flap', \
                'TC002_vPC_UP_Link_Flap', \
                'TC003_SA_Access_Link_Flap', \
                'TC004_vPC_Access_Link_Flap', \
                'TC005_SA_NVE_Flap', \
                'TC006_vPC_NVE_Flap', \
                'TC007_SA_Remove_Add_VN_Segment', \
                'TC008_vPC_Remove_Add_VN_Segment', \
                'TC009_SA_Loopback_Flap', \
                'TC010_vPC_Loopback_Flap', \
                'TC011_SA_Remove_Add_VLAN', \
                'TC012_vPC_Remove_Add_VLAN', \
                'TC013_Remove_Add_NVE_Configs', \
                'TC014_Remove_Add_BGP_Configs', \
                'TC015_VxLAN_CC', \
                'TC016_iCAM_Check', \
                'TC017_Config_Replace', \
                ))

'''
(pyats_feb_2021) bash-4.2$ echo $PYTHONPATH
/ws/jumashan-bgl/pyats_new/nxos:/ws/jumashan-bgl/pyats_feb_2021:/ws/jumashan-bgl/pyats_feb_2021:/ws/jumashan-bgl/pyats_feb_2021/projects:/auto/dc3-india/jumashan/automation/Genie/nexus-test-pyats:/auto/dc3-india/jumashan/automation/Genie/nexus-test-pyats/lib:/auto/dc3-india/jumashan/automation/Genie/nexus-test-pyats/lib/nxtest:

'''