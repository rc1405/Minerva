#!/bin/python
import pymongo
from dateutil.parser import parse

client = pymongo.MongoClient()
collection = client.minerva.alerts
flow = client.minerva.flow

i = 0
while True:
    collection.insert({ "payload_printable" : "HTTP/1.1 200 OK\r\nServer: Protocol HTTP\r\nContent-Length: 707\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n", "src_port" : 53063, "event_type" : "alert", "stream" : 1, "proto" : "TCP", "orig_timestamp" : "2015-09-12T18:13:02.402463-0400", "timestamp" : parse("2015-09-12T22:13:02.402Z"), "in_iface" : "eth1", "alert" : { "category" : "", "severity" : 1, "rev" : 1, "gid" : 1, "signature" : "Test HTTP", "action" : "allowed", "signature_id" : 999999 }, "src_ip" : "192.168.1.2", "logType" : "alert", "epoch" : 1442099582, "packet" : "JAHOhc9HBF/iBBUuLMA9PvAAAgICAg", "flow_id" : 20170296, "dest_ip" : "192.168.1.3", "dest_port" : 1119, "sensor" : "suri_ids01", "payload" : "SRijh2Q3ZTlfDxDYOT3GyMUNTiDA3YmRZT4z2NMfIwD0Dui4yLjIwNDQ0DQp0d3wwYTZmMDdmMjVjNDIwM2NiMmZkYmY2YTdkN2U5YXw4MWQ2Nzk0MOYjAwN2JkZGU2OGM2NjdjNHwyMDQ0NHw2LjIuMi4yMDQ0NA0KY258MGE2ZjA3ZjQ4NTI1YzQyMDNjYjJmZGJmNmE3ZDdlOWF8ODFkNjc5NDcwYjIwZTg1NmIwMDdiZGRlNjhjNjY3YzR8MjA0NDR8Ni4yLjIuMjA0NDQNCnNnfDBhNmYwN2Y0ODUyNWM0MjAzY2IyZmRiZjZhN2Q3ZTlhfDgxZDY3OTQ3MGIyMGU4NTZiMDA3YmRkZTY4YzY2N2M0fDIwNDQ0fDYuMi4yLjIwNDQ0DQoNCg==", "MINERVA_STATUS" : "OPEN" })
    #flow.insert({ "src_port" : 53063, "event_type" : "flow", "proto" : "TCP", "orig_timestamp" : "2015-08-29T16:56:35.001412-0400", "timestamp" : parse("2015-08-29T20:56:35.001Z"), "flow" : { "bytes_toclient" : 60, "pkts_toclient" : 1, "age" : 0, "state" : "closed", "start" : "2015-08-29T16:54:30.107261-0400", "reason" : "timeout", "pkts_toserver" : 1, "bytes_toserver" : 60, "end" : "2015-08-29T16:54:30.145541-0400" }, "tcp" : { "tcp_flags" : "14", "tcp_flags_tc" : "14", "ack" : True, "state" : "closed", "tcp_flags_ts" : "10", "rst" : True }, "src_ip" : "192.168.1.2", "logType" : "flow", "epoch" : 1440885395, "flow_id" : 42524104, "dest_port" : 1119, "sensor" : "suri_ids01", "dest_ip" : "192.168.1.3", "MINERVA_STATUS" : "OPEN" } )
    i = i + 1
    if i == 1000:
        break
