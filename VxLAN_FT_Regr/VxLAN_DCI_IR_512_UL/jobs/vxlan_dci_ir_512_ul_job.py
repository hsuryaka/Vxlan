# How to Run this Script
# bash-4.2$ cd /auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base
# bash-4.2$ source bin/activate
# (pyats_jdGrp_vxlan_automation_base) bash-4.2$
# (pyats_jdGrp_vxlan_automation_base) bash-4.2$ easypy -jobfile /ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_IR_512_UL/jobs/vxlan_dci_ir_512_ul_job.py --config-file /ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_IR_512_UL/configs/vxlan_dci_ir_512_ul_config.yaml -testbed /ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_IR_512_UL/testbed/VxLAN_DCI_IR_512_UL_Testbed.yaml

# EARMS RUN REPORT FOR KR2F CCO : https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/jumashan/archive/22-02/vxlan_dci_ir_512_ul_job.2022Feb09_16:52:25.362881.zip&atstype=ATS
# EARMS RUN REPORT FOR KR3F #52 :


from pyats.easypy import run
from pyats.datastructures.logic import And, Or, Not
import os

def main():
    tmp_path = os.path.dirname(os.path.abspath(__file__))
    test_path = tmp_path.split('/')
    test_path.pop()
    test_path.append('scripts')
    test_path.append('vxlan_dci_ir_512_ul.py')
    testscript = '/'.join(test_path)
    run(testscript, traffic_threshold = 2,tgn_connect = 0,\
        config_interface = 0,\
        config_ospf = 0,\
        config_bgp = 0,\
        config_keepalive_vrf = 0,\
        config_trmv6 = 0,\
        config_vpc = 0,\
        config_pim = 0,
        config_vxlan_global = 0,\
        config_bgp_global = 0, \
        config_vlan = 0,\
        config_vrf = 0,\
        config_svi = 0,\
        config_evpn = 0,\
        config_nve_global = 0,\
        config_nve_l2vni = 0,\
        config_nve_l3vni = 0,\
        config_loopback_intf = 0,\
        config_route_map = 0,\
        config_multisite = 0,\
        
        uids = Or('common_setup',\
                    'TC000_Verify_Steady_State',\
                    'TC001_vPC_BGW_NVE_Flap',\
                    'TC002_AC_BGW_BGW_NVE_Flap',\
                    'TC003_Site_1_LEAF_NVE_Flap',\
                    'TC004_Site_2_LEAF_NVE_Flap',\
                    'TC005_vPC_BGW_Fab_Link_Flap',\
                    'TC006_AC_BGW_Fab_Link_Flap',\
                    'TC007_Site_1_LEAF_Fab_Link_Flap',\
                    'TC008_Site_2_LEAF_Fab_Link_Flap',\
                    'TC009_vPC_BGW_DCI_Link_Flap',\
                    'TC010_AC_BGW_DCI_Link_Flap',\
                    'TC011_vPC_MultiSite_Loopback_Flap',\
                    'TC012_AC_MultiSite_Loopback_Flap',\
                    'TC013_vPC_IntraSite_Loopback_Flap',\
                    'TC014_AC_IntraSite_Loopback_Flap',\
                    'TC015_Site_1_Loopback_Flap',\
                    'TC016_Site_2_Loopback_Flap',\
                    'TC017_vPC_BGW_Domain_Flap',\
                    'TC018_vPC_BGW_MCT_Flap',\
                    'TC019_vPC_BGW_Leg_Flap',\
                    'TC020_vPC_BGW_Remove_Add_L2_VN_Segment',\
                    'TC021_vPC_BGW_Remove_Add_L3_VN_Segment',\
                    'TC022_AC_BGW_Remove_Add_L2_VN_Segment',\
                    'TC023_AC_BGW_Remove_Add_L3_VN_Segment',\
                    'TC024_vPC_BGW_Remove_Add_L2_VNI',\
                    'TC025_vPC_BGW_Remove_Add_L3_VNI',\
                    'TC026_AC_BGW_Remove_Add_L2_VNI',\
                    'TC027_AC_BGW_Remove_Add_L3_VNI',\
                    'TC028_vPC_BGW_Remove_Add_L2_VNI_Mcast_Grp',\
                    'TC029_vPC_BGW_Remove_Add_L3_VNI_Mcast_Grp',\
                    'TC030_AC_BGW_Remove_Add_L2_VNI_Mcast_Grp',\
                    'TC031_AC_BGW_Remove_Add_L3_VNI_Mcast_Grp',\
                    'TC032_vPC_BGW_Remove_Add_TRM_L2_VNI_IR',\
                    'TC033_vPC_BGW_Remove_Add_TRM_L3_VNI_IR',\
                    'TC034_AC_BGW_Remove_Add_TRM_L2_VNI_IR',\
                    'TC035_AC_BGW_Remove_Add_TRM_L3_VNI_IR',\
                    'TC036_vPC_BGW_Process_Restart',\
                    'TC037_AC_BGW_Process_Restart',\
                    'TC038_vPC_BGW_Clear_CLIs',\
                    'TC039_AC_BGW_Clear_CLIs',\
                    'TC040_vPC_BGW_VxLAN_CC',\
                    'TC041_AC_BGW_VxLAN_CC',\
                    'TC042_vPC_BGW_Config_Replace',\
                    'TC043_AC_BGW_Config_Replace',\
                    'TC044_vPC_BGW_iCAM',\
                    'TC045_AC_BGW_iCAM',\
                    'TC046_Verify_512_Underlay_Scale_on_vPC_BGW',\
                    'TC047_Verify_512_Underlay_Scale_on_AC_BGW',\
                    'TC048_vPC_BGW_L2VNI_SVI_Shut_UnShut',\
                    'TC049_AC_BGW_L2VNI_SVI_Shut_UnShut',\
                    'TC050_vPC_BGW_L3VNI_SVI_Shut_UnShut',\
                    'TC051_AC_BGW_L3VNI_SVI_Shut_UnShut',\
                    'TC052_RemovingFeatureNGMVPNOnBGW',\
                    'TC053_ShuttingDCILinksOnVPCPrimary',\
                    'TC054_ShuttingFabricLinksOnVPCPrimary',\
                    'TC055_ShuttingVPCPeerkeepalive',\
                    'TC056_SplitBrainScenario',\
                    'TC057_ModifyNVESourceLoopbackIPOnVPCPrimary',\
                    'TC058_RemoveDCILinkTrackingCliOnVPCPrimary',\
                    'TC059_RemoveFabricLinkTrackingCliOnVPCPrimary',\
                    'TC060_RemoveAddL3VNIonBothVPCSwitches',\
                    'TC061_RemoveAddMultisiteConfig',\
                    'TC062_NVESourceLoopbackFlapOnVPCPrimary',\
                    'TC063_VlanShutUnshutOnVPCSwitches',\
                    'TC064_VRFLiteLinkFlapOnVPCSwitches',\
                ))

'''
-----CAT /auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/bin/activate-----

(pyats_jdGrp_vxlan_automation_base) bash-4.2$ pwd
/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base
(pyats_jdGrp_vxlan_automation_base) bash-4.2$ cat bin/activate
# This file must be used with "source bin/activate" *from bash*
# you cannot run it directly

deactivate () {
    # reset old environment variables
    if [ -n "${_OLD_VIRTUAL_PATH:-}" ] ; then
        PATH="${_OLD_VIRTUAL_PATH:-}"
        export PATH
        unset _OLD_VIRTUAL_PATH
    fi
    if [ -n "${_OLD_VIRTUAL_PYTHONHOME:-}" ] ; then
        PYTHONHOME="${_OLD_VIRTUAL_PYTHONHOME:-}"
        export PYTHONHOME
        unset _OLD_VIRTUAL_PYTHONHOME
    fi

    # This should detect bash and zsh, which have a hash command that must
    # be called to get it to forget past commands.  Without forgetting
    # past commands the $PATH changes we made may not be respected
    if [ -n "${BASH:-}" -o -n "${ZSH_VERSION:-}" ] ; then
        hash -r
    fi

    if [ -n "${_OLD_VIRTUAL_PS1:-}" ] ; then
        PS1="${_OLD_VIRTUAL_PS1:-}"
        export PS1
        unset _OLD_VIRTUAL_PS1
    fi

    unset VIRTUAL_ENV
    if [ ! "$1" = "nondestructive" ] ; then
    # Self destruct!
        unset -f deactivate
    fi
}

# unset irrelevant variables
deactivate nondestructive

VIRTUAL_ENV="/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base"
export VIRTUAL_ENV

_OLD_VIRTUAL_PATH="$PATH"
PATH="$VIRTUAL_ENV/bin:$PATH"
export PATH

# unset PYTHONHOME if set
# this will fail if PYTHONHOME is set to the empty string (which is bad anyway)
# could use `if (set -u; : $PYTHONHOME) ;` in bash
if [ -n "${PYTHONHOME:-}" ] ; then
    _OLD_VIRTUAL_PYTHONHOME="${PYTHONHOME:-}"
    unset PYTHONHOME
fi

if [ -z "${VIRTUAL_ENV_DISABLE_PROMPT:-}" ] ; then
    _OLD_VIRTUAL_PS1="${PS1:-}"
    if [ "x(pyats_jdGrp_vxlan_automation_base) " != x ] ; then
        PS1="(pyats_jdGrp_vxlan_automation_base) ${PS1:-}"
    else
    if [ "`basename \"$VIRTUAL_ENV\"`" = "__" ] ; then
        # special case for Aspen magic directories
        # see http://www.zetadev.com/software/aspen/
        PS1="[`basename \`dirname \"$VIRTUAL_ENV\"\``] $PS1"
    else
        PS1="(`basename \"$VIRTUAL_ENV\"`)$PS1"
    fi
    fi
    export PS1
fi

# This should detect bash and zsh, which have a hash command that must
# be called to get it to forget past commands.  Without forgetting
# past commands the $PATH changes we made may not be respected
if [ -n "${BASH:-}" -o -n "${ZSH_VERSION:-}" ] ; then
    hash -r
fi

# BEGIN CUSTOM pyATS CONTENT
# --------------------------

#export PYTHONPATH="/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base:/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/projects:$PYTHONPATH"

#export PYTHONPATH="/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base:/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/projects:/auto/dc3-india/havadhut/automation/py_automation_develop/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_PYlib:$PYTHONPATH"

export PYTHONPATH="/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base:/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/projects:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/common_lib:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/feature_lib/l2:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/feature_lib/l3:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/feature_lib/security:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/feature_lib/vxlan:$PYTHONPATH"

echo ""
echo "Activating pyATS instance @ /auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base"
echo "--------------------------------------------------------------------"
echo "PYTHONPATH=$PYTHONPATH"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo ""
echo "If you are leveraging legacy Tcl-ATS libraries and functions,"
echo "make sure to source your 64-bit Tcl-ATS environment separately!"
echo "(or use the default one @ /auto/pysw/ats64)"
echo "--------------------------------------------------------------------"
echo ""

source /auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/nxos/nxos-env.sh
source /auto/pysw/ats64/env.sh
#source /auto/Nexus-n39K/N39K_Regression/ats-64/ats6.0.0/install/env.sh
#source /auto/dc3-india/jumashan/automation/envs/ixia_9_00_env.sh
source /auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/ixia_9.10_64bit_env.sh
(pyats_jdGrp_vxlan_automation_base) bash-4.2$

'''

'''

----PYTHONPATH------

(pyats_jdGrp_vxlan_automation_base) bash-4.2$ echo $PYTHONPATH
/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base:/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base:/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/projects:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/common_lib:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/feature_lib/l2:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/feature_lib/l3:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/feature_lib/security:/ws/jumashan-bgl/pyats_new/users/jumashan/vxlan_sundown/MyScripts/VxLAN_DCI_MCast/lib/feature_lib/vxlan::/auto/dc3-india/script_repository/IXIA_9.10_64bit/lib/hltapi/library/common/ixiangpf/python
(pyats_jdGrp_vxlan_automation_base) bash-4.2$ 

'''