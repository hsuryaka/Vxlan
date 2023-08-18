This folder consists of VxLAN TRM Distributed RP scripts.


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

| Testbed     | Clean Run Result    | Image Run on | Comments |
|:-------------:|:-------------:|:-----:|:-----:|
| WR EOR | [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/havadhut/archive/21-05/TRM_DIST_RP_job.2021May04_16:37:54.562833.zip&atstype=ATS) [Result_2](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/havadhut/archive/21-05/TRM_DIST_RP_job.2021May05_13:08:06.735559.zip&atstype=ATS) | K-DEV - 10.1(1)IKD9(0.177)| Failures due to [CSCvy18544](https://cdetsng.cisco.com/summary/#/defect/CSCvy18544) |
|Sundown| [Result_1]( https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-09/sundown_trm_dist_rp_job.2021Sep09_14:18:55.392814.zip&atstype=ATS)| | |
|Fretta| | | |