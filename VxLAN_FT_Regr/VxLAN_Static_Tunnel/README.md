This folder consists of VxLAN Static Tunnel Single Site scripts.


### **Topology Diagram:**

```python
                                            +-------------+
                                            |    SPINE    |
                                            +-------------+
                                           /               \\
                                          /                 \\
                                         /                   \\
                                        /                     \\
                                       /                       \\
                                      /                         \\
                            +-----------+                     +-----------+
                            |   LEAF-1  |                     |   LEAF-2  |
                            +-----------+                     +-----------+
                                  |                                 |
                                  |                                 |
                                IXIA                              IXIA
```

### **Device Type**

| Devices     | Type|
|:-------------:|:-------------:|
| SPINE | Any |
| LEAF-1 | FX3 |
| LEAF-2 | FX3 |

### **Number of Connections**

| Devices     | No.of Connections|
|:-------------:|:-------------:|
| SPINE-LEAF-1  |  1 |
| SPINE-LEAF-2  |  1 |
| LEAF-1-IXIA  |  1 |
| LEAF-2-IXIA  |  1 |

### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on | Archive Location | Comments |
|:-------------:|:-------------:|:-----:|:-----:|:-----:|
| WR EOR  | Not Supported | - | - | - |
| Sundown | [Result-log](https://earms-trade.cisco.com/tradeui/logs/details?archive=%2Fauto%2Fdc3-india%2Fjdasgupt_grp%2Fpyats_jdGrp_vxlan_automation_base%2Fusers%2Fpkanduri%2Farchive%2F21-05%2Fvxlan_static_tunnels_job.2021May25_12:06:04.886372.zip&atstype=ATS) | J Plus | Local Folder | - |
| Fretta  | Not Supported | - | - | - |