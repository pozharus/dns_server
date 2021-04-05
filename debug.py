import json

jsonObjs = {} #array with dictionaries
with open('dns.json') as dnsObjs:
    jsonObjs = json.load(dnsObjs)

zones = {} #array with json objects with key->"$original"

for item in jsonObjs:
    for key in item:
        zonename = item["$original"]
        zones[zonename] = item
        break

print(zones)            
        
