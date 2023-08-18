# To run the job:
# easypy <pyats_root>/examples/connection/job/connection_example_job.py \
#        -testbed_file \
#        <pyats_root>/examples/connection/etc/connection_example_conf.yaml
#            
# Description: This example uses a sample testbed, connects to a device
#              which name is passed from the job file,
#              and executes some commands. The goal is to show
#              how devices can be chosen dynamically and passed to the script.

import os
from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not

def main():
    # Find the location of the script in relation to the job file
    test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    #testscript = os.path.join(test_path, './scripts/L2_TRM.py')
    testscript = './VxLAN_Loop_Detection.py'
    configurationFile = './VxLAN_Loop_Detection_config.yaml'

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    # ...
    uut_devices = {}
    uut_devices['SPINE']        = 'SPINE'
    uut_devices['LEAF-1']       = 'Sundown-1'
    uut_devices['LEAF-2']       = 'Sundown-2'
    uut_devices['LEAF-3']       = 'Seoul-1'
    uut_devices['FAN-1']        = 'FAN-2'
    uut_devices['FAN-2']        = 'FAN-1'
    uut_devices['ixia']         = 'IXIA'
    #uut_devices = {}
    #uut_devices['SPINE']        = 'spine1'
    ##uut_devices['LB']           = 'LB'
    #uut_devices['LEAF-1']       = 'Elysian1'
    #uut_devices['LEAF-2']       = 'Tahoe1'
    #uut_devices['ixia']         = 'IXIA'
    
    script_flags = {'skip_device_config' : 0,'skip_tgen_config' : 0,'skip_device_cleanup' : 0}

    run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags)
    #, uids = Or('common_setup','DEVICE_BRINGUP','VERIFY_NETWORK','Vpc1_Access_sw_to_vpc2_acc_sw_Link_loop_detection','Vpc1_Access_sw_to_standalone_Link_loop_detection'))
    #run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags, uids = Or('common_setup','Collect_ngoam_techsupport'))
    #run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags, uids = Or('common_setup','ENABLE_L2_MCAST_CONFIGURATION','IXIA_CONFIGURATION','ENCAP_COS_MODIFY_25'))
    
    #, uids = Or('common_setup','ENABLE_L2_MCAST_CONFIGURATION','IXIA_CONFIGURATION','DSCP_ENCAP_DEFAULT_QOS','DSCP_ENCAP_DSCP_20','DSCP_ENCAP_TOS','DSCP_ENCAP_DSCP_TOS_REMARKING','L2_COS_TO_DSCP_VLAN_POLICY','DSCP_ENCAP_TOS_REMARK_VLAN_POLICY','DSCP_ENCAP_ING_EGR_L3VNI_DSCP','DSCP_ENCAP_ING_POLICE_EGR_L3VNI_DSCP',
    #'VERIFY_ACLQOS_PROCESS_RESTART','VERIFY_DEVICE_ASCII_RELOAD','DECAP_UNFM_INGR_NVE_EGR_INT_1','DECAP_UNFM_INGR_NVE_COS_REMARKING','DECAP_UNFM_INGR_NVE_COS_POLICE','DECAP_UNFM_ASCII_RELOAD','DECAP_PIPE_DSCP_MCAST','DECAP_PIPE_MCAST_TOS',
    #'DECAP_PIPE_INGR_NVE_EGR_DSCP','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_POLICE','DECAP_PIPE_INGR_NVE_L2_VLAN_POLICE','DECAP_PIPE_INGR_NVE_POLICE_L2_VLAN_POLICE','DECAP_PIPE_INGR_NVE_COS_REMARKING','DECAP_PIPE_INGR_NVE_COS_POLICE'))
       
    #uids = Or('common_setup','DEVICE_BRINGUP','VERIFY_NETWORK', 'IXIA_CONFIGURATION','L2_COS_TO_DSCP_ENCAP','DSCP_ENCAP_DEFAULT_QOS','DSCP_ENCAP_DSCP_20','DSCP_ENCAP_TOS','DSCP_ENCAP_DSCP_20_IPV6','DSCP_ENCAP_IP_ACL','DSCP_ENCAP_IP_COS_DSCP_REMARKING','DSCP_ENCAP_DSCP_TOS_REMARKING','DSCP_ENCAP_DSCP_DSCP_REMARKING','DSCP_ENCAP_DSCP_POLICE_REMARKING'
    #,'L2_COS_TO_DSCP_VLAN_POLICY','DSCP_ENCAP_DSCP_20_VLAN_POLICY','DSCP_ENCAP_TOS_VLAN_POLICY','L2_COS_TO_COS_ENCAP_VLAN_POLICY','DSCP_ENCAP_DSCP_REMARK_VLAN_POLICY','DSCP_ENCAP_TOS_REMARK_VLAN_POLICY','DSCP_ENCAP_ING_EGR_L3VNI_DSCP','DSCP_ENCAP_PORT_FLAP','DSCP_ENCAP_MODIFY_DSCP','L2_COS_TO_COS_ENCAP_VLAN_POLICY',
    # 'DSCP_ENCAP_DSCP_MODIFY','DSCP_ENCAP_DSCP_POLICE_REMARKING','ENCAP_COS_MODIFY','DSCP_ENCAP_TOS_MODIFY','DSCP_ENCAP_TOS_POLICE_MODIFY','ENCAP_COS_POLICE_MODIFY','DSCP_ENCAP_DSCP_POLICE_MODIFY','VERIFY_ACLQOS_PROCESS_RESTART','VERIFY_DEVICE_ASCII_RELOAD','VERIFY_DEVICE_RELOAD','ENCAP_COS_POLICING','VERIFY_SWITCH_MODE_CHANGE','DSCP_ENCAP_VLAN_TOS_POLICE',
    # 'DSCP_ENCAP_VLAN_DSCP_POLICE','DSCP_ENCAP_ING_POLICE_EGR_L3VNI_DSCP','DECAP_TOS_POLICE_UNIFM_1','DECAP_UNFM_INGR_NVE_EGR_INT_1','DECAP_UNFM_INGR_NVE_TOS','DECAP_DSCP_MODIFY_POLICE_UNIFM_1','DECAP_UNFM_ACLQOS_RESTART','DECAP_UNFM_RELOAD','DECAP_UNFM_ASCII_RELOAD','DECAP_UNFM_SWITCHMODE_CHG','DECAP_UNFM_NVE_FLAP',
    # 'DECAP_UNFM_LOOPBACK_FLAP','DECAP_UNFM_RESTART_BGP','DECAP_UNFM_NVE_RESTART','DECAP_UNFM_NVE_DELETE_ADD',,'DECAP_PIPE_INGR_NVE_DSCP','DECAP_PIPE_INGR_NVE_TOS','DECAP_PIPE_INGR_NVE_EGR_DSCP','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP','DECAP_PIPE_INGR_NVE_DSCPTOS','DECAP_PIPE_INGR_NVE_POLICER_DSCP','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_POLICE'
    # ,'DECAP_PIPE_INGR_NVE_COS_REMARKING','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_POLICE','DECAP_PIPE_IPV6','DECAP_PIPE_INGR_NVE_L2_VLAN_POLICE','DECAP_PIPE_INGR_NVE_COS_REMARKING','DECAP_PIPE_INGR_NVE_COS_POLICE','DECAP_PIPE_INGR_NVE_POLICE_L2_VLAN_POLICE','DECAP_PIPE_INGR_NVE_ACL_DSCP','DECAP_PIPE_UNFM_TOGGLE','DECAP_PIPE_NVE_STATS'
    # ,'DECAP_UNFM_INGR_NVE_COS_REMARKING','DECAP_UNFM_INGR_NVE_COS_POLICE','DSCP_ENCAP_DSCP_MCAST','DSCP_ENCAP_MCAST_TOS','DECAP_PIPE_DSCP_MCAST') 
    #uids = Or('common_setup', 'DEVICE_BRINGUP', 'VERIFY_NETWORK','L2_COS_TO_DSCP_ENCAP','DSCP_ENCAP_DEFAULT_QOS')
    
    #uids = Or('common_setup', 'DEVICE_BRINGUP', 'IXIA_CONFIGURATION', 'VXLAN_DISRUPTIVE_VERIFICATION'))
