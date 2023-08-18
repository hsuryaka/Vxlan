This folder consists of VxLAN EVPN PIP VIP scripts.


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
                                    |ENDNODE FX2|     
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
| LEAF-3 | FX3  |
| ACCESS | ANY  |


### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location | Comments |
|:-------------:|:-------------:|:-----:|:-----:|:-----:|

|Sundown| [Result_logs](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-05/Sundown_VxLAN_PIPVIP_JobFile.2021May24_14:33:17.669827.zip&atstype=ATS) | 
