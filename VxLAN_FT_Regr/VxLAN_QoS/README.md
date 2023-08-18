This folder consists of VxLAN Qos scripts.


### **Topology Diagram:**

```python
                                                             +-------------+
                                   +-------------------------|    SPINE    |
                                   |                         +-------------+
                                   |                          |         |   
                                   |                         |           |  
                                   |                       |               |
                                   |                     |                   |
                            +-----------+          +-----------+          +-----------+
                            |   LEAF-1  |==========|   LEAF-2  |          |   LEAF-3  |
                            +-----------+          +-----------+          +-----------+
                              |     \                  /     |                  |      
                            Ixia      \               /     Ixia                |
                                        \            /                          |
                                        +-----------+                     
                                        |   FAN-1   |---Ixia                  Ixia
                                        +-----------+                     
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
| LEAF-1-FAN | 4 | 4 |
| LEAF-2-FAN | 4 | 4 |
| FAN-1-IXIA  |  1 | 1 |
| LEAF-1-IXIA  |  1 | 1 |
| LEAF-2-IXIA  |  1 | 1 |
| LEAF-3-IXIA  |  1 | 1 |

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location |
|:-------------:|:-------------:|:-----:|:-----:|
| WR EOR | [Result_1]() | | |
|Sundown| [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-04/vxlan_qos_job.2021Apr28_14:57:22.044433.zip&atstype=ATS)| 
|Fretta| | | |