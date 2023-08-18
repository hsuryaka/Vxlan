This folder consists of VxLAN DSVNI Single Site scripts.


### **Topology Diagram:**

```python
                                            +-------------+
                                            |    SPINE    |
                                            +-------------+
                                           /       |      \
                                          /        |       \
                                         /         |        \
                                        /          |         \
                                       /           |          \
                              +-----------+    +-----------+   +-----------+
                      ixia----|   LEAF-1  |====|   LEAF-2  |   |   LEAF-3  |
                              +-----------+    +-----------+   +-----------+
                                   \              /   |              |
                                    \            /    |              |
                                     \          /   ixia           ixia
                                      \        /                           
                                    +-----------+     
                                    |   FAN     |     
                                    +-----------+     
                                         |
                                         |
                                        ixia
```

### **Device Type**

| Devices     | Type|
|:-------------:|:-------------:|
| SPINE | Any |
| LEAF-1 | FX3 / WR-EOR |
| LEAF-2 | FX3 / WR-EOR |
| LEAF-3 | FX3 / WR-EOR |
| ACCESS | ANY |

### **Number of Connections**

| Devices     | FX3 No.of Connections | WR EOR No.of Connections|
|:-------------:|:-------------:|:-------------:|
| SPINE-LEAF-1  |  4 | 4 |
| SPINE-LEAF-2  |  4 | 4 |
| SPINE-LEAF-3  |  4 | 4 |
| LEAF-1-LEAF-2 | 2 | 2 |
| LEAF-1-FAN | 2 | 2 |
| LEAF-2-FAN | 2 | 2 |
| FAN-IXIA  |  1 | 1 |
| LEAF-3-IXIA  |  1 | 1 |

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location | Comments |
|:-------------:|:-------------:|:-----:|:-----:|:-----:|
| WR EOR | [Result_logs](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/havadhut/archive/21-05/VxLAN_DSVNI_JobFile.2021May11_12:03:15.442183.zip&atstype=ATS) | K-DEV - 10.1(1)IKD9(0.195) | Current Folder | Failures due to [CSCvy30601](https://cdetsng.cisco.com/summary/#/defect/CSCvy30601) |
|Sundown| [Result_logs](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-05/VxLAN_DSVNI_JobFile.2021May19_10:30:38.023257.zip&atstype=ATS) | Kerry Nightly | Current Folder | Failure due to [CSCvy37494](https://cdetsng.cisco.com/summary/#/defect/CSCvy37494) |
|Fretta| Not Supported | - | - | - |