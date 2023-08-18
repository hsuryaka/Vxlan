This folder consists of VxLAN TRM VPC BL scripts.


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
                            |   LEAF-1  |==========|   LEAF-2  |          |   LEAF-3  |          |   LEAF-4  |
                            +-----------+          +-----------+          +-----------+          +-----------+
                              |     \                  /     |                  |                      |
                            Ixia      \               /     Ixia              Ixia                    Ixia
                                        \            /                        
                                        +-----------+          +-----------+
                                        |   EXT-RP  |----------|    CORE   |---Ixia
                                        +-----------+          +-----------+
```

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location |
|:-------------:|:-------------:|:-----:|:-----:|
| WR EOR | [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/havadhut/archive/21-05/TRM_VPC_BL_job.2021May06_22:20:46.740868.zip&atstype=ATS) | K-DEV - 10.1(1)IKD9(0.145) | [Archive](https://bitbucket-eng-sjc1.cisco.com/bitbucket/projects/NXOS/repos/nxos/browse/test/N39kRegression/test/functional/Vxlan/VxLAN_FT_Regr/VxLAN_TRM/L3_TRM_VPC_BL/result_archive/)|
|Sundown| [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-05/sundown_l3trmvpcbl_job.2021May24_15:40:11.476865.zip&atstype=ATS)| | |
|Fretta| | | |