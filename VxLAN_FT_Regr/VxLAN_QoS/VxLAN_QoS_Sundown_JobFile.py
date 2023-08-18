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
    testscript = './VxLAN_QOS.py'
    configurationFile = './VxLAN_QOS_config.yaml'

    # Do some logic here to determine which devices to use
    # and pass these device names as script arguments
    # ...
    # uut_devices = {}
    # uut_devices['SPINE']        = 'spine1'
    # uut_devices['LEAF-1']       = 'Tecate1'
    # uut_devices['LEAF-2']       = 'Tecate2'
    # uut_devices['LEAF-3']       = 'Elysian1'
    # uut_devices['FAN-1']        = 'Access1'
    # #uut_devices['FAN-2']        = 'FAN-2'
    # uut_devices['ixia']         = 'IXIA'
    uut_devices = {}
    uut_devices['SPINE']        = 'SPINE'
    #uut_devices['LB']           = 'LB'
    uut_devices['LEAF-1']       = 'Sundown-1'
    uut_devices['LEAF-2']       = 'Sundown-2'
    uut_devices['LEAF-3']       = 'Sundown-3'
    uut_devices['FAN-1']        = 'FAN-2'
    #uut_devices['FAN-2']        = 'FAN-2'
    uut_devices['ixia']         = 'IXIA'
    
    script_flags = {'skip_device_config' : 0,'skip_tgen_config' : 0,'skip_device_cleanup' : 0}
    #run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags)
    #run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags, uids = Or('common_setup','DEVICE_BRINGUP','VERIFY_NETWORK','ENABLE_L2_MCAST_CONFIGURATION','IXIA_CONFIGURATION','DSCP_ENCAP_MCAST_TOS_6'))
    # run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags, uids = Or('common_setup','VERIFY_NETWORK','ENABLE_L2_MCAST_CONFIGURATION','IXIA_CONFIGURATION','L2_COS_TO_DSCP_ENCAP_1','DSCP_ENCAP_MCAST_TOS_6','DSCP_ENCAP_DSCP_20_IPV6_3', 'DSCP_ENCAP_ING_EGR_L3VNI_DSCP_21', 'DSCP_ENCAP_ING_POLICE_EGR_L3VNI_DSCP_22', 'VERIFY_ACLQOS_PROCESS_RESTART_34', 'DSCP_ENCAP_VLAN_TOS_POLICE_33', \
    #                                                                                                                                 'DECAP_UNFM_INGR_NVE_EGR_INT_39', 'DECAP_UNFM_INGR_NVE_COS_REMARKING_43', 'DECAP_UNFM_INGR_NVE_COS_POLICE_46','DECAP_UNFM_LOOPBACK_FLAP_54','DECAP_UNFM_INGR_NVE_TOS_45','DECAP_PIPE_DSCP_MCAST_60','DECAP_PIPE_MCAST_TOS_62','DECAP_PIPE_INGR_NVE_EGR_DSCP_64','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_67','DECAP_PIPE_IPV6_73',\
    #                                                                                                                                 'DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_POLICE_72','DECAP_PIPE_INGR_NVE_L2_VLAN_POLICE_74','DECAP_PIPE_INGR_NVE_POLICE_L2_VLAN_POLICE_75','DECAP_PIPE_INGR_NVE_COS_REMARKING_66','DECAP_PIPE_INGR_NVE_COS_POLICE_70'))
    # run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags, uids = Or('common_setup','VERIFY_NETWORK','ENABLE_L2_MCAST_CONFIGURATION','IXIA_CONFIGURATION','VERIFY_SWITCH_MODE_CHANGE_37','ENCAP_COS_POLICING_11','DSCP_ENCAP_VLAN_DSCP_POLICE_32','DSCP_ENCAP_VLAN_TOS_POLICE_33','DECAP_TOS_POLICE_UNIFM_38','DECAP_DSCP_MODIFY_POLICE_UNIFM_47','çç', 'DSCP_ENCAP_DSCP_MCAST_4',\
    #                 'DECAP_UNFM_INGR_NVE_EGR_INT_39','DECAP_UNFM_INGR_NVE_COS_REMARKING_43','DECAP_UNFM_INGR_NVE_COS_POLICE_46','DECAP_UNFM_ACLQOS_RESTART_49','DECAP_UNFM_SWITCHMODE_CHG_52','DECAP_UNFM_NVE_FLAP_53','DECAP_UNFM_LOOPBACK_FLAP_54','L2_COS_TO_DSCP_VLAN_POLICY_13','DSCP_ENCAP_TOS_5','DSCP_ENCAP_MCAST_TOS_6','DSCP_ENCAP_DSCP_MCAST_4','L2_COS_TO_DSCP_ENCAP_1',\
    #                 'DECAP_UNFM_INGR_NVE_TOS_45','DECAP_UNFM_RESTART_BGP_55','DECAP_UNFM_NVE_RESTART_56','DECAP_UNFM_NVE_DELETE_ADD_57','DECAP_PIPE_INGR_NVE_DSCP_59','DECAP_PIPE_DSCP_MCAST_60','DECAP_PIPE_MCAST_TOS_62','DECAP_PIPE_INGR_NVE_ACL_DSCP_63','DECAP_PIPE_UNFM_TOGGLE_76','DECAP_PIPE_NVE_STATS_77',\
    #                 'DECAP_PIPE_INGR_NVE_TOS_61','DECAP_PIPE_INGR_NVE_EGR_DSCP_64','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_67','DECAP_PIPE_INGR_NVE_DSCPTOS_68','DECAP_PIPE_INGR_NVE_POLICER_DSCP_71','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_POLICE_72','DECAP_PIPE_IPV6_73','DECAP_PIPE_INGR_NVE_L2_VLAN_POLICE_74',\
    #                 'DECAP_PIPE_INGR_NVE_POLICE_L2_VLAN_POLICE_75','DECAP_PIPE_INGR_NVE_COS_REMARKING_66','DECAP_PIPE_INGR_NVE_COS_POLICE_70'))
    # run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags, uids = Or('common_setup','VERIFY_NETWORK','ENABLE_L2_MCAST_CONFIGURATION','IXIA_CONFIGURATION','L2_COS_TO_DSCP_ENCAP_1', 'DSCP_ENCAP_DEFAULT_QOS__1', \
    #                  'DSCP_ENCAP_MCAST_TOS_6','DSCP_ENCAP_TOS_5','DSCP_ENCAP_DSCP_20_IPV6_3','DSCP_ENCAP_IP_ACL_7','DSCP_ENCAP_IP_COS_DSCP_REMARKING_8','DSCP_ENCAP_DSCP_DSCP_REMARKING_9','DSCP_ENCAP_DSCP_POLICE_REMARKING_12','DSCP_ENCAP_DSCP_TOS_REMARKING_10',\
    #                  'L2_COS_TO_DSCP_VLAN_POLICY_13','DSCP_ENCAP_DSCP_20_VLAN_POLICY_14','DSCP_ENCAP_TOS_VLAN_POLICY_15','L2_COS_TO_COS_ENCAP_VLAN_POLICY_16','DSCP_ENCAP_DSCP_REMARK_VLAN_POLICY_17','DSCP_ENCAP_TOS_REMARK_VLAN_POLICY_18','DSCP_ENCAP_ING_EGR_L3VNI_DSCP_21',\
    #                  'DSCP_ENCAP_ING_POLICE_EGR_L3VNI_DSCP_22','DSCP_ENCAP_PORT_FLAP_23','DSCP_ENCAP_MODIFY_DSCP_26','ENCAP_COS_MODIFY_25','DSCP_ENCAP_DSCP_MODIFY_29','DSCP_ENCAP_TOS_MODIFY_30','DSCP_ENCAP_TOS_POLICE_MODIFY_20','DSCP_ENCAP_DSCP_POLICE_MODIFY_19','ENCAP_COS_POLICE_MODIFY_31',\
    #                  'VERIFY_ACLQOS_PROCESS_RESTART_34','VERIFY_SWITCH_MODE_CHANGE_37','ENCAP_COS_POLICING_11','DSCP_ENCAP_VLAN_DSCP_POLICE_32','DSCP_ENCAP_VLAN_TOS_POLICE_33','DECAP_TOS_POLICE_UNIFM_38','DECAP_DSCP_MODIFY_POLICE_UNIFM_47','DSCP_ENCAP_DSCP_20_2', 'DSCP_ENCAP_DSCP_MCAST_4',\
    #                  'DECAP_UNFM_INGR_NVE_EGR_INT_39','DECAP_UNFM_INGR_NVE_COS_REMARKING_43','DECAP_UNFM_INGR_NVE_COS_POLICE_46','DECAP_UNFM_ACLQOS_RESTART_49','DECAP_UNFM_SWITCHMODE_CHG_52','DECAP_UNFM_NVE_FLAP_53','DECAP_UNFM_LOOPBACK_FLAP_54',\
    #                  'DECAP_UNFM_INGR_NVE_TOS_45','DECAP_UNFM_RESTART_BGP_55','DECAP_UNFM_NVE_RESTART_56','DECAP_UNFM_NVE_DELETE_ADD_57','DECAP_PIPE_INGR_NVE_DSCP_59','DECAP_PIPE_DSCP_MCAST_60','DECAP_PIPE_MCAST_TOS_62','DECAP_PIPE_INGR_NVE_ACL_DSCP_63','DECAP_PIPE_UNFM_TOGGLE_76','DECAP_PIPE_NVE_STATS_77',\
    #                  'DECAP_PIPE_INGR_NVE_TOS_61','DECAP_PIPE_INGR_NVE_EGR_DSCP_64','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_67','DECAP_PIPE_INGR_NVE_DSCPTOS_68','DECAP_PIPE_INGR_NVE_POLICER_DSCP_71','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_POLICE_72','DECAP_PIPE_IPV6_73','DECAP_PIPE_INGR_NVE_L2_VLAN_POLICE_74',\
    #                  'DECAP_PIPE_INGR_NVE_POLICE_L2_VLAN_POLICE_75','DECAP_PIPE_INGR_NVE_COS_REMARKING_66','DECAP_PIPE_INGR_NVE_COS_POLICE_70'))
    # 
    # 
    # run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags, uids = Or('common_setup','DEVICE_BRINGUP','VERIFY_NETWORK','ENABLE_L2_MCAST_CONFIGURATION','IXIA_CONFIGURATION','L2_COS_TO_DSCP_ENCAP_1','DSCP_ENCAP_DSCP_MCAST_4','DSCP_ENCAP_MCAST_TOS_6','DECAP_UNFM_INGR_NVE_EGR_INT_39',\
    #                 'DSCP_ENCAP_IP_COS_DSCP_REMARKING_8','VERIFY_SWITCH_MODE_CHANGE_37','DECAP_UNFM_INGR_NVE_COS_REMARKING_43','DECAP_UNFM_INGR_NVE_COS_POLICE_46','DECAP_UNFM_INGR_NVE_TOS_45','DECAP_PIPE_INGR_NVE_DSCP_59','DECAP_PIPE_INGR_NVE_ACL_DSCP_63','DECAP_PIPE_UNFM_TOGGLE_76','DECAP_PIPE_NVE_STATS_77','DECAP_PIPE_INGR_NVE_TOS_61',\
    #                 'DECAP_PIPE_INGR_NVE_EGR_DSCP_64','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_67','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_POLICE_72','DECAP_PIPE_IPV6_73','DECAP_PIPE_INGR_NVE_COS_REMARKING_66','DECAP_PIPE_INGR_NVE_COS_POLICE_70'))
    # 
    run(testscript=testscript, uut_list=uut_devices, configurationFile = configurationFile,script_flags = script_flags, uids = Or('common_setup','VERIFY_NETWORK','ENABLE_L2_MCAST_CONFIGURATION','IXIA_CONFIGURATION','DSCP_ENCAP_MCAST_TOS_6','VERIFY_ACLQOS_PROCESS_RESTART_34','DECAP_UNFM_INGR_NVE_EGR_INT_39','DECAP_UNFM_INGR_NVE_COS_REMARKING_43','DECAP_UNFM_INGR_NVE_COS_POLICE_46','DECAP_UNFM_INGR_NVE_TOS_45','DECAP_PIPE_MCAST_TOS_62','DECAP_PIPE_INGR_NVE_EGR_DSCP_64','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_67','DECAP_PIPE_INGR_NVE_REMARKING_EGR_DSCP_POLICE_72','DECAP_PIPE_IPV6_73','DECAP_PIPE_INGR_NVE_L2_VLAN_POLICE_74','DECAP_PIPE_INGR_NVE_POLICE_L2_VLAN_POLICE_75','DECAP_PIPE_INGR_NVE_COS_REMARKING_66','DECAP_PIPE_INGR_NVE_COS_POLICE_70'))
    
    
    