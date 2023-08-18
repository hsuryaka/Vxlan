This folder consists of VxLAN EVPN PIP VIP scripts.


### **Topology Diagram:**

```python
                                            +-------------+     
                                            |      BL     |----- IXIA
                                            +-------------+     
                                                   |
                                                   |
                                                   |
                                            +-------------+
                                            |    SPINE    |
                                            +-------------+
                                           /       |       \\
                                          /        |        \\
                                         /         |         \\
                                        /          |          \\
                                       /           |           \\
                                      /            |            \\
                            +-----------+    +-----------+    +-----------+
                            |   LEAF-1  |    |   LEAF-2  |    |   LEAF-3  |
                            +-----------+    +-----------+    +-----------+
                                   \\              |                /
                                    \\             |               / 
                                     \\            |              /         <---- Two links each
                                      \\           |             /
                                    +------------------------------+
                                    |            PGW               |
                                    +------------------------------+
                                                   |    
                                                   |      
                                                  IXIA 
```

### **Device Type**

| Devices     | Type|
|:-------------:|:-------------:|
| SPINE  | Any  |
| LEAF-1 | FX3  |
| LEAF-2 | FX3  |
| LEAF-3 | FX3  |
| PGW    | ANY  |

### **Library Dependencies**

Need below Library for the script to run.
https://wwwin-github.cisco.com/nexus-test-team/nexus-test-automation/blob/v3-non-golden/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_PYlib/vxlanEVPN_PVNF_lib.py

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location | Comments |
|:-------------:|:-------------:|:-----:|:-----:|:-----:|
|FX3| [Result_logs](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/havadhut/automation/pyats_envs/pyats_venv_02_2022/users/havadhut/archive/22-02/VxLAN_PVNF_ND_ISSU_job.2022Feb17_11:04:21.171737.zip&atstype=ATS) | 

### **PyATS Env Details**

|PYTHONPATH|```<PyATS NxOS Git path>:<PyATS VENV Path>:<PyATS VENV Path>/projects:<Path to VxLAN_PYlib>:<Path to Vxlan/ folder>:<Path to nexus-test-pyats/lib>:<Path to nexus-test-pyats/nxtest>:<Path to IXIA Libs>```|