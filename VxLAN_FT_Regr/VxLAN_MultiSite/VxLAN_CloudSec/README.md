This folder consists of VxLAN CloudSec scripts.


### **Topology Diagram:**

```python
                                             +----------------+           +-----------------+
                                   +---------|    DCI BOX 1   |-----------|    DCI BOX 2    |------------+
                                   |         +----------------+            +----------------+           |          
                                   |                  |                            |                    |
                                   |   +-------------------------------------------+                    | 
                                   |   |              |                                                 |
                                   |   |              +----------------------------------------------+  |
                                   |   |                                                             |  | 
                                   |   |                                                             |  | 
                            +-------------+                                                        +-------------+             
                            |   BGW-1     |                                                         |   BGW - 2  |
                            +-------------+                                                        +------------+           
                                   |                                                                   |  
                                   |                                                                   |  
                                   |                                                                   |  
                            +-----------+                                                         +-----------+
                            |   LEAF-1  |                                                          |   LEAF-2  |
                            +-----------+                                                         +-----------+  
                                   |                                                                    |
                                   |                                                                    |
                                   |                                                                    |
                                 Ixia                                                                  Ixia



```
### **Run Reports per Test-Bed**

| Testbed     | Clean Run Result    | Image Run on |
|:-------------:|:-------------:|:-----:|
| FX3 |  |  |
|Sundown| [Result_1](https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/jdasgupt_grp/pyats_jdGrp_vxlan_automation_base/users/pkanduri/archive/21-07/sundown_ms_cloudsec_job.2021Jul02_17:32:06.418919.zip&atstype=ATS) | |
|Fretta| | |