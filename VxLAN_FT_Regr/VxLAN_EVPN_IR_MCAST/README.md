This folder consists of VxLAN EVPN IR MCast scripts.


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

### **File Structure**

| Job File     | TB Yaml File    | Testbed|
|:-------------:|:-------------:|:-----:|
| [VxLAN_EVPN_IR_MCAST_BRCM_job.py](https://bitbucket-eng-sjc1.cisco.com/bitbucket/projects/NXOS/repos/nxos/browse/test/N39kRegression/test/functional/Vxlan/QA_Regression/VxLAN_FT_Regr/VxLAN_EVPN_IR_MCAST/VxLAN_EVPN_IR_MCAST_BRCM_job.py)           | [VxLAN_EVPN_IR_MCAST_BRCM_TB.yaml](https://bitbucket-eng-sjc1.cisco.com/bitbucket/projects/NXOS/repos/nxos/browse/test/N39kRegression/test/functional/Vxlan/QA_Regression/VxLAN_FT_Regr/VxLAN_EVPN_IR_MCAST/VxLAN_EVPN_IR_MCAST_BRCM_TB.yaml)      | BRCM    |
| [VxLAN_EVPN_IR_MCAST_FX3_job.py](https://bitbucket-eng-sjc1.cisco.com/bitbucket/projects/NXOS/repos/nxos/browse/test/N39kRegression/test/functional/Vxlan/QA_Regression/VxLAN_FT_Regr/VxLAN_EVPN_IR_MCAST/VxLAN_EVPN_IR_MCAST_FX3_job.py)            | [VxLAN_EVPN_IR_MCAST_FX3_TB.yaml](https://bitbucket-eng-sjc1.cisco.com/bitbucket/projects/NXOS/repos/nxos/browse/test/N39kRegression/test/functional/Vxlan/QA_Regression/VxLAN_FT_Regr/VxLAN_EVPN_IR_MCAST/VxLAN_EVPN_IR_MCAST_FX3_TB.yaml)       | FX3     |
| [VxLAN_EVPN_IR_MCAST_WR_EOR_job.py](https://bitbucket-eng-sjc1.cisco.com/bitbucket/projects/NXOS/repos/nxos/browse/test/N39kRegression/test/functional/Vxlan/QA_Regression/VxLAN_FT_Regr/VxLAN_EVPN_IR_MCAST/VxLAN_EVPN_IR_MCAST_WR_EOR_job.py)         | [VxLAN_EVPN_IR_MCAST_WR_EOR_TB.yaml](https://bitbucket-eng-sjc1.cisco.com/bitbucket/projects/NXOS/repos/nxos/browse/test/N39kRegression/test/functional/Vxlan/QA_Regression/VxLAN_FT_Regr/VxLAN_EVPN_IR_MCAST/VxLAN_EVPN_IR_MCAST_WR_EOR_TB.yaml)    | WR EOR  |
| [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-04/vxlan_evpn_job1.2021Apr09_10:49:11.990808.zip&atstype=ATS) | FX3|
