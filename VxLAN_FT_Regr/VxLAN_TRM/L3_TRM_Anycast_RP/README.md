This folder consists of VxLAN TRM Anycast RP scripts.


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
| WR EOR | [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/havadhut/archive/21-04/TRM_Anycast_RP_job.2021Apr28_17:31:39.512949.zip&atstype=ATS) | K-DEV - 10.1(1)IKD9(0.177)| Failures due to [CSCvy18544](https://cdetsng.cisco.com/summary/#/defect/CSCvy18544) |
|Sundown|[Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/20-12/sundown_trm_dist_rp_job.2020Dec23_13:08:05.197278.zip&atstype=ATS)[Result_2](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-01/sundown_trm_dist_rp_job.2021Jan25_12:58:42.570820.zip&atstype=ATS) | | |
|Fretta| | | |