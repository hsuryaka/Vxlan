This folder consists of VxLAN LOOP Detetction scripts.


### **Topology Diagram:**

```python
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
                        --- |   LEAF-1  |====|   LEAF-2  |    |   LEAF-3  |
                        |    +-----------+    +-----------+    +-----------+
                        |    \\           \  /         /         |   |    |
                        |     \\           /\         /          |   |    |
                        |      \\         /   \      /           |   |    |
                        |       \\       /      \   /            |   |    |
                        |     +-----------+    +---------+       |   |    |
                        |     |           |____|          |-------   |    |  
                        |     |    Fan1   |----| Fan-2    |          |    |  
                        |     |-----------|    |----------|        Ixia   |
                        |           |                                     |
                        |           |                                     |
                        |           |                                     |
                        |          ixia                                   |
                        |_________________________________________________|

```

### **Device Type**

| Devices     | Type|
|:-------------:|:-------------:|
| SPINE | Any |
| LEAF-1 | FX3 / WR-EOR |
| LEAF-2 | FX3 / WR-EOR |
| LEAF-3 | FX3 / WR-EOR |
| FAN-1 | ANY |
| FAN-2 | ANY |

### **Number of Connections**

| Devices     | FX3 No.of Connections | WR EOR No.of Connections|
|:-------------:|:-------------:|:-------------:|
| SPINE-LEAF-1  |  4 | 4 |
| SPINE-LEAF-2  |  4 | 4 |
| SPINE-LEAF-3  |  4 | 4 |
| LEAF-1-LEAF-2 | 5 | 5 |
| LEAF-1-LEAF-3 | 1 | 1 |
| LEAF-1-FAN-1 | 4 | 4 |
| LEAF-1-FAN-2 | 4 | 4 |
| LEAF-2-FAN-1 | 3 | 3 |
| LEAF-2-FAN-2 | 3 | 3 |
| LEAF-3-FAN-2 | 2 | 2 |
| FAN-1-FAN-2 | 2 | 2 |
| FAN-1-IXIA  |  1 | 1 |
| LEAF-3-IXIA  |  1 | 1 |

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Comments |
|:-------------:|:-------------:|:-----:|:-----:|
| WR EOR | [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=%2Fauto%2Fdc3-india%2Fjdasgupt_grp%2FVxLAN_Regression%2Fusers%2Fhavadhut%2Farchive%2F21-05%2FVxLAN_Loop_Detection_job_WR_EOR.2021May28_14:32:58.665591.zip&atstype=ATS) | Kerry - 10.2(0.52)| Failures due to [CSCvy42903](https://cdetsng.cisco.com/summary/#/defect/CSCvy42903) |
|Sundown| [Result_1]( https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-06/vxlan_loop_detection_job.2021Jun30_22:17:49.612609.zip&atstype=ATS)| | |