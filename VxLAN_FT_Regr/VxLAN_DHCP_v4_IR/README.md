This script is written and followed the pyATS framwork.
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
> pyats run job Project_Job.py -t Project_Testbed.yaml 

## **Topology:**

```
                                                  ----------------
                                                  |    SPINE     |
                                                  ----------------
                                                    .    .    .
                                                  .      .      .
                                                .        .        .
                                              .          .          .
                                            .            .            .
                                          .              .              .
                                        .                .                .
                          ----------------        -------------      -------------
            IXIA -------  |   VTEP-1     | ------ |   VTEP-2  |      |  VTEP-3   |  ----- 2 x IXIA
                          ----------------        -------------      -------------
                                      \           /          |
                                       \         /           |
                                        \       /            |
                                         \     /            IXIA
                                          \   /                           
                                           \ /                            
                                     -------------- 
                    IXIA ----------- |  FANOUT    | 
                                     -------------- 
```

### Topological Notes

- All the three VTEPs are Cloudscale Platform devices with single-site topology.
- All the devices except spine have the T.gen Ports.
- Here, VTEP-3 onlt have two T.Gen ports and other VTEPs and FANOUT deives have one T.Gen Port.
- We used IXIA for the T.Gen.

### Report Log

- Pass Log : https://earms-trade.cisco.com/tradeui/logs/details?archive=%2Fws%2Frudshah-bgl%2Fautomation%2Fpyats_venvs%2Fpyats_venv_06_2023%2Fusers%2Frudshah%2Farchive%2F23-07%2FProject_Job.2023Jul13_09:42:36.539729.zip&atstype=ATS