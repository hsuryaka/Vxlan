from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    # run api launches a testscript as an individual task.
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = os.path.join(test_path, './WR_EOR/n39k_vxlan_oam_script.py')
    run(testscript
    ,uids =Or('common_setup','setupConfigVxlan','setupTgen','VXLAN-OAM-FUNC-039'))
    #                         'VXLAN-OAM-FUNC-001', 'VXLAN-OAM-FUNC-002', 'VXLAN-OAM-FUNC-004','VXLAN-OAM-FUNC-005',
    #                         'VXLAN-OAM-FUNC-039', 'VXLAN-OAM-FUNC-040'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupTgen','VXLAN-OAM-FUNC-026','VXLAN-OAM-FUNC-027'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','VXLAN-OAM-FUNC-028','VXLAN-OAM-FUNC-029','VXLAN-OAM-FUNC-030','VXLAN-OAM-FUNC-031','VXLAN-OAM-FUNC-032','VXLAN-OAM-FUNC-033','VXLAN-OAM-FUNC-034','VXLAN-OAM-FUNC-035','VXLAN-OAM-FUNC-036','VXLAN-OAM-FUNC-037','VXLAN-OAM-FUNC-038','VXLAN-OAM-FUNC-039','VXLAN-OAM-FUNC-040','VXLAN-OAM-FUNC-041','VXLAN-OAM-FUNC-042','VXLAN-OAM-FUNC-043','VXLAN-OAM-FUNC-044','VXLAN-OAM-FUNC-045','VXLAN-OAM-FUNC-046','VXLAN-OAM-FUNC-047'))
    #run(testscript,uids =Or('common_setup'))
