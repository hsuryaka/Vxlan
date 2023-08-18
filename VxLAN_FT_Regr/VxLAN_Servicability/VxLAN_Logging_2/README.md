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
pyats run job ./VxLAN_EVPN_Logg_2_0_job.py --testbed-file ./VxLAN_EVPN_Logg_2_0_TB.yaml --clean-file VxLAN_EVPN_Logg_2_0_clean.yaml --invoke-clean
```

## **Topology:**

```python
                                          +-----------------------------+
                                          |            SPINE            |
                                          +-----------------------------+
                                           /       |                 |      
                                          /        |                 |      
                                         /         |                 |      
                                        /          |                 |      
                                       /           |                 |      
                              +-----------+    +-----------+   +-----------+
                              |   LEAF-1  |====|   LEAF-2  |   |   LEAF-3  |
                              +-----------+    +-----------+   +-----------+
                                   \              /              |  
                                    \            /               |  
                                     \          /              ixia 
                                      \        /                    
                                    +-------------+                 
                                    |    ACCESS   |                 
                                    +-------------+                 
                                           |  
                                           |  
                                         ixia 
```

### Topological Notes

- This script needs to be run on 3 different platforms (FX3, GX-EOR , Fretta)
- SPINE, LEAF-1, LEAF-2, LEAF-3 has to be CloudScale devices.
- Every links between the LEAF's and SPINE are 4 links.
- Every links between the LEAF-1 to LEAF-2 are 4 links.
- Every links between the LEAF-1 and LEAF-2 to ACCESS are 2 links each.
- IXIA config file is included in the folder. (IXOS : 9.10 patch3, IXNCFG : NR1F_NBM_FlexStats.ixncfg)
- The script takes the IXIA file and dumps on the IXIA VM.

### PASS Report

Archive file also added to GIT.
https://earms-trade.cisco.com/tradeui/logs/details?archive=%2Fauto%2Fdc3-india%2Fhavadhut%2Fautomation%2Fpyats_envs%2Fpyats_venv_02_2022%2Fusers%2Fhavadhut%2Farchive%2F22-07%2FVxLAN_EVPN_Logg_2_0_job.2022Jul22_07:23:21.687606.zip&atstype=ATS