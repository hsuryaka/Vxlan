This folder consists of VxLAN V6 scripts.


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
| SPINE  | Any  |
| LEAF-1 | FX3  |
| LEAF-2 | FX3  |
| LEAF-3 | FX3/EX  |
| ACCESS | ANY  |


### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location | Comments |
|:-------------:|:-------------:|:-----:|:-----:|:-----:|

|Sundown| [Result_logs](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/20-11/sundown_VxlanV6_job.2020Nov30_12:31:54.074691.zip&atstype=ATS) [Result_2](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/20-11/sundown_VxlanV6_job.2020Nov29_14:07:08.737026.zip&atstype=ATS)| 
