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
/auto/dc3-india/absr/automation/vxlan/custom_libs
```

## **Running the Script:**
Use the below line to run the script.
```
pyats run job Evpn_Bh_job.py --testbed VxLAN_MSite_TB.yaml
```

## **Topology:**

```python
                                                  ----------------
                                                  |    DCI       |
                                                  ----------------
                                                    .    .    .
                                                  .      .      .
                                                .        .        .
                                              .          .          .
                                            .            .            .
                                          .              .              .
                                        .                .                .
                          ----------------        -------------      -------------
            ixia -------  |   S1_BGW-1   | ------ |   S1_BGW-2 |      |  S2_BGW-1 |
                          ----------------        -------------      -------------
                                  |   \           /    |                   |
                                  |    \         /     |                   |
                                  |     \       /      |                   |
                                  |      \     /       |                   |
                                  |       \   /        |                   |
                                  |        \ /         |                   |
                            --------------  /\  ---------------      --------------
           ixia ----------- |  Access    | /  \ |   SPINE     |      |   LEAF     | ----- ixia
                            --------------      ---------------      --------------
                                                      |
                                                      |
                                                      |
                                                ------------
                                                |  LEAF    | ------ ixia
                                                ------------
```

### Topological Notes

- Every links between the devices are 4 links.
- ALL Devices are cloudeScale devices in the above topo.and same topo is used in WF-EOR devices
- IXIA config file is . (IXOS : 9.10 patch3, IXNCFG : ixia_esi_cfg.ixncfg)
- The script takes care of all ixia configurations.
- Ixia Requires Vxlan emulation License
- before running script enable Tcam craving and relod the devices to effect it.

### Report
- FX-3 pass Log : 
https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/hsuryaka/pyATS/automation/pyats_venvs/pyats_venv_08_2022/users/hsuryaka/archive/23-01/Evpn_Bh_job.2023Jan17_16:52:25.539099.zip&atstype=ATS

WF-EOR PASS LOG :
1. https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/hsuryaka/pyATS/automation/pyats_venvs/pyats_venv_08_2022/users/hsuryaka/archive/23-01/Evpn_Bh_job.2023Jan15_22:40:57.405522.zip&atstype=ATS 
  
1. https://earms-trade.cisco.com/tradeui/logs/details?archive=/auto/dc3-india/hsuryaka/pyATS/automation/pyats_venvs/pyats_venv_08_2022/users/hsuryaka/archive/23-01/Evpn_Bh_job.2023Jan16_17:13:50.127700.zip&atstype=ATS 