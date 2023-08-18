Install otm infra first:
OTM Installation:
 
Create a folder under pyats (mdp), and checkout the otm code
 
[my_pyats_latest] bgl-ads-2772:129> cd mdp/
my_pyats_latest] bgl-ads-2772:126> pwd
/nobackup/mmahibal/my_pyats_latest/mdp
[my_pyats_latest] bgl-ads-2772:130> ls
[my_pyats_latest] bgl-ads-2772:131> git init
Reinitialized existing Git repository in /nobackup/mmahibal/my_pyats_latest/mdp/.git/
[my_pyats_latest] bgl-ads-2772:132> git clone https://gitlab-sjc.cisco.com/vsheela/otm_infra.git
Cloning into 'otm_infra'...
Username for 'https://gitlab-sjc.cisco.com': mmahibal
Password for 'https://mmahibal@gitlab-sjc.cisco.com':
remote: Enumerating objects: 73, done.
remote: Counting objects: 100% (73/73), done.
remote: Compressing objects: 100% (30/30), done.
remote: Total 1645 (delta 43), reused 73 (delta 43)
Receiving objects: 100% (1645/1645), 15.14 MiB | 4.75 MiB/s, done.
Resolving deltas: 100% (1023/1023), done.
[my_pyats_latest] bgl-ads-2772:133> ls
otm_infra
 
 
Install few more python packages if needed,
 pip install xmltodict
 pip install deepdiff
 pip install lxml
 pip install yang
 pip install yang.connector
pip install rest.connector
 
 
OTM Execution:
After sourcing pyats, source otm.csh 
source /nobackup/mmahibal/my_pyats_latest/env.csh
source /auto/pysw/ats64/env.csh
source /nobackup/mmahibal/my_pyats_latest/mdp/otm_infra/otm.csh 
 



/auto/dc3/absr/pyats/users/absr/otm_infra/jobs

-testbed_file : /auto/dc3/absr/pyats/users/absr/otm_infra/inputs/absr_single_device.yaml
-testcase_file : /auto/dc3/absr/pyats/users/absr/otm_infra/inputs/nc_merge_triggers.yaml

list of test cases files:
absr_testsuite.yaml
bulk_config_reload.yaml
nc_create_triggers.yaml
nc_delete_triggers.yaml
nc_merge_triggers.yaml
nc_remove_triggers.yaml
nc_replace_triggers.yaml
rest_delete_triggers.yaml
rest_post_triggers.yaml
rest_put_triggers.yaml

Run job using:
pyats] sjc-ads-1779:87> pwd                                                                                                
/auto/dc3/absr/pyats/users/absr/otm_infra/jobs

easypy otm_new_ns.py -testbed_file ../inputs/absr_single_device.yaml --testcase_file ../inputs/nc_merge_triggers.yaml


Source the following files:
40  0:44    cd /auto/dc3/absr/pyats
42  0:44    source env.csh
43  0:44    source /auto/pysw/ats64/env.csh
