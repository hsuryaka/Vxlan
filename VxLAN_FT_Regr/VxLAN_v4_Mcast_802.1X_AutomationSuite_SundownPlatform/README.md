
***This directory contains the complete automation suite for the feature 802.1X. Otherwise called the DOT1X feature. It is a client-server-based access control and authentication protocol in the Nexus Operating System. This automation suite was written completely by Genie Format. This suite used the single-site spine-leaf topology with CloudScale platform devices. This readme mentions the complete suite details along with a topology explanation for your reference. Which will help you port the suite or reuse this suite for further testing. This suite planned three separate Jab files to run and get the fastest report without any interruption, and all the steps are mentioned below clearly.***

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

>**Configuration Baseline :** VxLAN BGP EVPN IPv4 with Multicast

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
dot1x_job_vpcFV.py
dot1x_job_vpcMM.py
dot1x_job_vpcTriggers.py
dot1x_script.py
dot1x_TB.yaml
dot1x_verify.yaml
```
### **STEP : 02**
>Make sure two different set of IXIA configuration files are placed in the current or specific working directory.
List of IXIA configuration files:
```
VxLAN_802.1X_AutomationSuite_MM_Set-A.ixncfg
VxLAN_802.1X_AutomationSuite_MM_Set-B.ixncfg
VxLAN_802.1X_AutomationSuite_Set-A.ixncfg
VxLAN_802.1X_AutomationSuite_Set-B.ixncfg
```
### **STEP : 03**
>Please make sure all the `realpath` paths that are integrated into the job files are correct with respect to your working directory, along with the correct file name with a specific extension.

### **STEP : 04**
>Once your devices are ready for automation, please erase all the configuration (configure terminal ; write erase ; reload) and make sure to run only with plain startup configuration, which will come with the same NX-OS, and close all the consoles properly. Mostly, this automation suite will run via console connectivity.

### **STEP : 05**
>Please make sure you are entered into the current working directory once you have sourced your automation environment.

### **STEP : 06**
>First, run the VPC Functional Verify job in your automation environment. For example, 
```
pyats run job dot1x_job_vpcFV.py -t dot1x_TB.yaml --clean-file dot1x_clean.yaml --invoke-clean
```
>and get the VPC Functional Verify Report Logs.

### **STEP : 07**
>Similarly, run the VPC Mac-Move job in your automation environment. For example, 
```
pyats run job dot1x_job_vpcMM.py -t dot1x_TB.yaml --clean-file dot1x_clean.yaml --invoke-clean
```
>and get the VPC Mac-Move Report Logs.

### **STEP : 08**
>Similarly, run the VPC Triggers job in your automation environment. For example,
```
pyats run job dot1x_job_vpcTriggers.py -t dot1x_TB.yaml --clean-file dot1x_clean.yaml --issu_upgrade_image '/images/jhajajam_QA/nxos64-cs.10.4.0.IMG9.0.289.F.bin.upg' --invoke-clean
```
>and get the VPC Triggers Report Logs. Now, all three VPC pair combinations have been finished.

### **STEP : 09**
>Now, all the combination of jobs have been Executed. Hence, the 802.1X automation has been finished.

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
                             |    FANOUT    |                     |    FEX101    |  ******** 2xT.Gen
                             ----------------                     ----------------


..... = 40G
----- = 10G
***** = 10G
///// = 10G
\\\\\ = 10G
●●● = 40G Breakout (AOC-Preferred)

```

# **DOT1X Automation Suite - Report Logs**

>### ***802.1X Functional Verify :***  https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jhajajam-bgl/automation/pyats_venvs/pyats_venv_03_2023/users/jhajajam/archive/23-06/dot1x_job_vpcFV.2023Jun17_09:38:56.341442.zip&atstype=ATS

>### ***802.1X Functional Mac-Move Verify :*** https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jhajajam-bgl/automation/pyats_venvs/pyats_venv_03_2023/users/jhajajam/archive/23-06/dot1x_job_vpcMM.2023Jun11_18:11:30.569515.zip&atstype=ATS

>### ***802.1X Triggers with all the FI :*** https://earms-trade.cisco.com/tradeui/logs/details?archive=/ws/jhajajam-bgl/automation/pyats_venvs/pyats_venv_03_2023/users/jhajajam/archive/23-06/dot1x_job_vpcTriggers.2023Jun17_13:14:42.399436.zip&atstype=ATS

# **🚀802.1X Automation Suite Author Information**

>### **NAME :** Abhijith S R Urala 

>### **CONTACT :** absr@cisco.com

>### **GROUP :** Nexus India VxLAN DevTest Group, Cisco Systems Inc.