from pyats.easypy import run
from pyats.datastructures.logic import And, Not, Or
import os

def main():

    # run api launches a testscript as an individual task.
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    testscript = os.path.join(test_path, './VxLAN_PVMAP_script.py')
    run(testscript)
    #run(testscript,uids =Or('common_setup','setupTgen','VXLAN-PMAP-FUNC-004'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupPortMappingVxlanConf','setupTgen','VXLAN-PMAP-FUNC-009'))
    #run(testscript,uids =Or('common_setup','setupPortMappingVxlanConf','setSupTgen','VXLAN-PMAP-FUNC-001'))
    #run(testscript,uids =Or('common_setup','setupConfigVxlan','setupPortMappingVxlanConf','setupTgen','VXLAN-PMAP-FUNC-006','VXLAN-PMAP-FUNC-007','VXLAN-PMAP-FUNC-008','VXLAN-PMAP-FUNC-009','VXLAN-PMAP-FUNC-010','VXLAN-PMAP-FUNC-011','VXLAN-PMAP-FUNC-012','VXLAN-PMAP-FUNC-013','VXLAN-PMAP-FUNC-014','VXLAN-PMAP-FUNC-015','VXLAN-PMAP-FUNC-016','VXLAN-PMAP-FUNC-017','VXLAN-PMAP-FUNC-018'))
