
import json
import requests

"""
Modify these please
"""
url='http://10.197.127.116/ins'
switchuser='admin'
switchpassword='nbv12345'

myheaders={'content-type':'application/json'}
payload={
  "ins_api":{
  "version": "1.0",
  "type": "cli_conf",
  "chunk": "0",
  "sid": "1",
  "input": "interface e1/33 ; switchport vlan mapping enable",
  "output_format": "json"}
}

response = requests.post(url,data=json.dumps(payload), headers=myheaders,auth=(switchuser,switchpassword)).json()
output = json.dumps(response, indent=4, sort_keys=True)
print(output)
