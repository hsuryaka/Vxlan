
***This directory contains the complete automation suite for the feature 802.1X. Otherwise called the DOT1X feature. It is a client-server-based access control and authentication protocol in the Nexus Operating System. This automation suite was written completely by Genie Format. This suite used the single-site spine-leaf topology with CloudScale platform devices. This readme mentions the complete suite details along with a topology explanation for your reference. Which will help you port the suite or reuse this suite for further testing. This suite planned five separate Jab files to run and get the fastest report without any interruption, and all the steps are mentioned below clearly.***

# **Repositories to be downloaded**

>Below Repositories are needed for the script to run. Please git clone these to any common location.

### **SJC Genie Repository**
- **nexus-pyats-test :** https://wwwin-github.cisco.com/nexus-test-team/nexus-test-pyats
- **Repo Path :** https://wwwin-github.cisco.com/nexus-test-team/nexus-test-pyats/tree/master/src/forwarding/vxlan

### **India VxLAN Team Repository**
- **nexus-test-automation :** https://wwwin-github.cisco.com/nexus-test-team/nexus-test-automation
- **Repo Path :** https://wwwin-github.cisco.com/nexus-test-team/nexus-test-automation/tree/v3-non-golden/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan

## **Setting up the PYTHONPATH:**

>Below are the paths which should be present in `PYTHONPATH` ,
For example, let us assume that the above Repositories are clone to location `/ws/jhajajam-bgl/`

```
/ws/user_id/nexus-test-pyats:
/ws/user_id/nexus-test-pyats/lib:
/ws/user_id/nexus-test-pyats/lib/nxtest:
/ws/user_id/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan:
/ws/user_id/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_PYlib:
```

>Finally add the `IXIA` library path.

```
/auto/dc3-india/script_repository/IXIA_9.10_64bit/lib/hltapi/library/common/ixiangpf/python
/auto/dc3-india/absr/automation/vxlan/custom_libs
```

# **Automation Suite Details:**

>**Configuration Baseline :** VxLAN BGP EVPN IPv6 with Ingress Replication (IR)

>**Topology Type :** Singel-Site with Fabric Extender

>**Suppoerted PIDs :** CloudScale Platform like the Sundown Family

>**T.Gen Used :** IXIA Traffic Generator powered by Keysight Technologies Inc.

>**IXIA Chassics version :** 9.10.2000.29

>**IXIA Licence Installed :** IXIA IxNetwork Opt SW 802.1x emulation

>**IXIA API version :** 9.10.2007.46 (used for this Automation Suite, same version is preferred)

>**Framework Used:** pyATS Genie

# **Follow the Steps to Run the script**
 
### **STEP : 01**
>Make sure all the listed files are placed under the current working directory. List of Automation Suite Files:
```
dot1x_clean.yaml
dot1x_config.yaml
dot1x_grun.yaml
dot1x_job_vmctFV.py
dot1x_job_vmctTriggers.py
dot1x_job_vpcFV.py
dot1x_job_vpcMM.py
dot1x_job_vpcTriggers.py
dot1x_script.py
dot1x_TB.yaml
dot1x_verify.yaml
```
### **STEP : 2**
>Make sure two different IXIA configuration files are placed in the current or specific working directory.
List of IXIA configuration files:
```
VxLAN_802.1X_AutomationSuite_MM_Set-A.ixncfg
VxLAN_802.1X_AutomationSuite_MM_Set-B.ixncfg
VxLAN_802.1X_AutomationSuite_Set-A.ixncfg
VxLAN_802.1X_AutomationSuite_Set-B.ixncfg
```
### **STEP : 3**
>Please make sure all the `realpath` paths that are integrated into the job files are correct with respect to your working directory, along with the correct file name with a specific extension.
 
### **STEP : 4**
>Once your devices are ready for automation, please erase all the configuration (write erase ; reload) and make sure to run only plain startup configuration, which will come with the same NX-OS, and close all the consoles properly. Mostly, this automation suite will run via console connectivity.
 
### **STEP : 5**
>Please make sure you are entered into the current working directory once you have sourced your automation environment.

### **STEP : 6**
>First, run the VPC Functional Verify job in your automation environment. For example, 
```
pyats run job dot1x_job_vpcFV.py -t dot1x_TB.yaml --clean-file dot1x_clean.yaml --invoke-clean
```
>and get the VPC Functional Verify Report Logs.

### **STEP : 7**
>Similarly, run the VPC Mac-Move job in your automation environment. For example, 
```
pyats run job dot1x_job_vpcMM.py -t dot1x_TB.yaml --clean-file dot1x_clean.yaml --invoke-clean
```
>and get the VPC Mac-Move Report Logs.

### **STEP : 8**
>Similarly, run the VPC Triggers job in your automation environment. For example,
```
pyats run job dot1x_job_vpcTriggers.py -t dot1x_TB.yaml --clean-file dot1x_clean.yaml --issu_upgrade_image '/images/jhajajam_QA/nxos64-cs.10.4.0.IMG9.0.289.F.bin.upg' --invoke-clean
```
>and get the VPC Triggers Report Logs. Now, all three VPC pair combinations have been finished.

### **STEP : 9**
>Then, run the VMCT Functional Verify job in your automation environment. For example,
```
pyats run job dot1x_job_vmctFV.py -t dot1x_TB.yaml --clean-file dot1x_clean.yaml --invoke-clean
```
>and get the VMCT Triggers Report Logs.

### **STEP : 10**
>Similarly, run the VMCT Triggers job in your automation environment. For example,
```
pyats run job dot1x_job_vmctTriggers.py -t dot1x_TB.yaml --clean-file dot1x_clean.yaml --issu_upgrade_image '/images/jhajajam_QA/nxos64-cs.10.4.0.IMG9.0.289.F.bin.upg' --invoke-clean
```
>and get the VPC Mac-Move Report Logs.
 
### **STEP : 11**
>Now, all the combinations of jobs have been Executed. Hence, the 802.1X automation has been finished.

# **Reference DOT1X Topology with Dotted Diagram**

```

                                              ----------------
                                              |     SPINE    |
                                              ----------------
                                                .    .    .
                                              .      .      .
                                            .        .        .
                                          .          .          .
                                        .            .            .
                                      .              .              .
                                    .                .                .
                    ----------------        ----------------      ----------------
    2xT.Gen ********|    VTEP-1    | ------ |    VTEP-2    |      |    VTEP-3    |  ******** 2xT.Gen
                    ----------------        ----------------      ----------------
                                  \          /          *                ●
                                   \        /           *                ●
                                    \      /            *                ●
                                     \    /             *              / /\ \
                                      \  /           2xT.Gen          / /  \ \
                                       \/                            / /    \ \
                             ----------------                     ----------------
                             |    FANOUT    |                     |    FEX101     |  ******** 2xT.Gen
                             ----------------                     ----------------


..... = 40G
----- = 10G
***** = 10G
///// = 10G
\\\\\ = 10G
●●● = 40G Breakout (AOC-Preferred)

```

# **DOT1X Automation Suite - Report Logs**

>## **802.1X with VPC Pair :**

### ***802.1X VPC Functional Verify :*** https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jhajajam-bgl/automation/pyats_venvs/pyats_venv_03_2023/users/jhajajam/archive/23-05/dot1x_job.2023May21_16:58:40.513115.zip&atstype=ATS

### ***802.1X VPC Functional Mac-Move Verify :*** https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jhajajam-bgl/automation/pyats_venvs/pyats_venv_03_2023/users/jhajajam/archive/23-05/dot1x_job.2023May18_18:57:07.379925.zip&atstype=ATS

### ***802.1X VPC Triggers with all the FI :*** https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jhajajam-bgl/automation/pyats_venvs/pyats_venv_03_2023/users/jhajajam/archive/23-06/dot1x_job_vpcTriggers.2023Jun18_03:14:36.701743.zip&atstype=ATS


>## **802.1X with VMCT Pair :**

### ***802.1X VMCT Functional Verify :*** https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jhajajam-bgl/automation/pyats_venvs/pyats_venv_03_2023/users/jhajajam/archive/23-05/dot1x_job_vmctFV.2023May29_23:29:49.015006.zip&atstype=ATS

### ***802.1X VMCT Triggers with all the FI :*** https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jhajajam-bgl/automation/pyats_venvs/pyats_venv_03_2023/users/jhajajam/archive/23-05/dot1x_job_vmctTriggers.2023May29_19:24:22.766702.zip&atstype=ATS


# **🚀802.1X Author Information**

>### **NAME :** Abhijith S R Urala 

>### **CONTACT :** absr@cisco.com

>### **GROUP :** Nexus India VxLAN DevTest Group, Cisco Systems Inc.