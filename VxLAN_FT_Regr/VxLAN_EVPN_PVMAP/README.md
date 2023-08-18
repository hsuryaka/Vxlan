This folder consists of VxLAN EVPN PVMAP scripts.


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
                                        +-----------+                     +-----------+
                                        |   FAN-1   |---Ixia              |    FAN-2  |---Ixia
                                        +-----------+                     +-----------+
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
| LEAF-1-LEAF-2 | 2 | 2 |
| LEAF-1-FAN | 4 | 4 |
| LEAF-2-FAN | 4 | 4 |
| FAN-1-IXIA  |  1 | 1 |
| FAN-2-IXIA  |  1 | 1 |
| LEAF-1-IXIA  |  1 | 1 |
| LEAF-2-IXIA  |  1 | 1 |

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location |
|:-------------:|:-------------:|:-----:|:-----:|
| WR EOR | [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/havadhut/archive/21-03/n9k_vxlan_pvmap_eor_job.2021Mar02_13:21:57.315794.zip&atstype=ATS) | J-PLUS 118 | [Archive](https://bitbucket-eng-sjc1.cisco.com/bitbucket/projects/NXOS/repos/nxos/browse/test/N39kRegression/test/functional/Vxlan/VxLAN_FT_Regr/VxLAN_EVPN_PVMAP/WR_EOR/result_archive) |
|Sundown| [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-05/n39k_vxlan_pvmap_job.2021May10_12:43:26.101255.zip&atstype=ATS)| 
|Fretta| | | |