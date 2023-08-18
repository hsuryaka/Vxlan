This script is written in Genie way using SJC VxLAN Genie Bring up and Libraries.
Please follow the steps below for running the script.

## **Repositories to be downloaded:**
Below Repositories are needed for the script to run. Please git clone these to any common location.

### SJC Genie Repository
- nexus-pyats-test : https://wwwin-github.cisco.com/nexus-test-team/nexus-test-pyats
- Repo Path : https://wwwin-github.cisco.com/nexus-test-team/nexus-test-pyats/tree/master/src/forwarding/vxlan

### India VxLAN Team Repository
- nexus-test-automation : https://wwwin-github.cisco.com/nexus-test-team/nexus-test-automation
- Repo Path : https://wwwin-github.cisco.com/nexus-test-team/nexus-test-automation/tree/v3-non-golden/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan

## **Setting up the PYTHONPATH:**

Below are the paths which should be present in PYTHONPATH

For example, let us assume that the above Repositories are clone to location "/ws/user_id/"

```
/ws/user_id/nexus-test-pyats:
/ws/user_id/nexus-test-pyats/lib:
/ws/user_id/nexus-test-pyats/lib/nxtest:
/ws/user_id/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan:
/ws/user_id/nexus-test-automation/eor/regression/nxos/test/N39kRegression/test/functional/Vxlan/VxLAN_PYlib:
```

Finally add IXIA library path.
```
/auto/dc3-india/script_repository/IXIA_9.10_64bit/lib/hltapi/library/common/ixiangpf/python
```

## **Running the Script:**
Use the below line to run the script.
```
pyats run job ./vxlanv4_evpn_gre_regression_job.py --testbed-file vxlanv4_evpn_fx3_gre_TB.yaml
```

## **Topology:**

```python
                                          +------------------------------+
                                          |            NODE03            |--- ixia
                                          +------------------------------+
                                            /       |                 |            
               +-----------+               /        |                 |             
               |  NODE06   |---------------------|  |                 |              
               +-----------+\            /       |  |                 |               
                    |        \          /        |  |                 |                
                    |         +-----------+    +-----------+   +-----------+    
                  ixia        | NODE01    |====|  NODE04   |   |  NODE02   |    
                              +-----------+    +-----------+   +-----------+    
                                |  \              /    |          |             
                                |   \            /     |          |                
                              ixia   \          /    ixia       ixia               
                                      \        /                                    
                                    +-------------+                  
                                    |   NODE05    |                  
                                    +-------------+                    
                                           |                                
                                           |                                
                                         ixia 
```

### Topological Notes

- Every links between the devices are 4 links.
- ALL Devices are cloudeScale devices in the above topo.
- IXIA config file is included in the folder. (IXOS : 9.10 patch3, IXNCFG : VxLAN+GRE_Regression.ixncfg)
- The script takes the IXIA file and dumps on the IXIA VM.

### Report
- Pass Logs build Niles 168 : https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/pkanduri/automation/pyats_venvs/pyats_venv_06_2022/users/pkanduri/archive/22-07/vxlanv4_evpn_gre_regression_job.2022Jul13_16:51:58.257045.zip&atstype=ATS
