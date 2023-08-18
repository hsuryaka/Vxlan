This folder consists of VxLAN CC scripts.


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
| LEAF-1 | BRCM |
| LEAF-2 | BRCM |
| LEAF-3 | BRCM |
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
| FAN-1-IXIA  |  1 | 1 |
| LEAF-1-IXIA  |  1 | 1 |
| LEAF-2-IXIA  |  1 | 1 |
| LEAF-3-IXIA  |  1 | 1 |

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location |
|:-------------:|:-------------:|:-----:|:-----:|
|BRCM| [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/20-08/IPlusB_BRCM_VxLAN_CC_Reg_job.2020Aug31_16:23:17.179534.zip&atstype=ATS)| 
