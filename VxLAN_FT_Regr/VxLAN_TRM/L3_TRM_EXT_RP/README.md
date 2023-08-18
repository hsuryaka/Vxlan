This folder consists of VxLAN TRM External RP scripts.


### **Topology Diagram:**

```python
                                                             +-------------+
                                   +-------------------------|    SPINE    |--------------------------+
                                   |                         +-------------+                          |
                                   |                          |         |                             |
                                   |                         |           |                            |
                                   |                       |               |                          |
                                   |                     |                   |                        |
                            +-----------+          +-----------+          +-----------+          +-----------+
                     Ixia---|   LEAF-1  |==========|   LEAF-2  |          |   LEAF-3  |          |   LEAF-4  |---Ixia
                            +-----------+          +-----------+          +-----------+        / +-----------+
                                    \                  /     |              |    |           /
                                      \               /     Ixia          Ixia   |         /
                                        \            /                           |       /
                                        +-----------+                     +-----------+          +-----------+
                                        |   BRCM-2  |                     |   EXT-RP  |----------|    CORE   |---Ixia
                                        +-----------+                     +-----------+          +-----------+
                                              |
                                              |
                                             Ixia
```

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on |
|:-------------:|:-------------:|:-----:|
| WR EOR | [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/havadhut/archive/21-04/TRM_EXT_RP_job.2021Apr27_18:31:28.225861.zip&atstype=ATS) [Result_2](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/havadhut/archive/21-04/TRM_EXT_RP_job.2021Apr28_11:02:14.024548.zip&atstype=ATS) | K-DEV - 10.1(1)IKD9(0.145)|
|Sundown| | |
|Fretta| | |