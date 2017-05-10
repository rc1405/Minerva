'''
    Copyright (C) 2015  Ryan M Cote.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    Author: Ryan M Cote <minervaconsole@gmail.com>
'''

import collections
import time
import datetime
import hashlib
import bson
import json

import pymongo
from collections import OrderedDict

class alert_console(object):
    '''Setup Initial Parameters'''
    def __init__(self, minerva_core):
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']
        db = minerva_core.get_db()
        self.alerts = db.alerts
        self.flow = db.flow
        self.dns = db.dns
        self.http = db.http
        self.sessions = db.sessions
        self.sort = OrderedDict()
        self.sort['_id.severity'] = pymongo.DESCENDING
        self.sort['timestamp'] = pymongo.ASCENDING

    #NEW STUFF
    '''Function to gather alerts to present to console'''
    def get_alerts(self, STATUS='OPEN'):
        def map_ids(bsonid):
            return str(bsonid)

        def map_alerts(event):
            new_event = event['_id']
            hash_string = ''
            new_event['sig_hash'] = hashlib.md5(json.dumps(event['_id'])).hexdigest()
            new_event['ids'] = ",".join(map(map_ids, event['ids']))
            new_event['timestamp'] = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            new_event['count'] = event['count']
            return new_event

        results = map(map_alerts, list(self.alerts.aggregate([{
            "$match": {
                "MINERVA_STATUS": STATUS
            }},{
            "$group": {
              "_id": {
                "sensor": "$sensor",
                "proto": "$proto",
                "src_ip": "$src_ip",
                "src_port": "$src_port",
                "dest_ip": "$dest_ip",
                "dest_port": "$dest_port",
                "signature": "$alert.signature",
                "category": "$alert.category",
                "severity": "$alert.severity",
                "sid": "$alert.signature_id",
                "rev": "$alert.rev",
                "gid": "$alert.gid"
              },
              "ids": {
                "$push": "$_id"
              },
              "count": {
                "$sum": 1
              },
              "timestamp": {
                "$max": "$timestamp"
              }
            }},{
            "$sort": self.sort
              #"_id.severity": pymongo.DESCENDING,
              #"timestamp": pymongo.ASCENDING
            #}},{
            },{
              "$limit": self.sizeLimit
            }
          
          ])))

        return results


    def get_ip_count(self):
        def map_ips(event):
            event['label'] = event.pop('_id')
            return event

        results = map(map_ips, list(self.flow.aggregate([{
            "$match": {
                "timestamp": {
                    "$gte": datetime.datetime.utcnow() - datetime.timedelta(days=1)
                }
            }},{
            "$project": {
                "ips": [
                    "$src_ip",
                    "$dest_ip"
                ]
            }},{
            "$unwind": "$ips"
            },{
            "$group": {
                "_id": "$ips",
                "count": {
                    "$sum": 1
                }
            }},{
            "$sort": {
              "count": -1
            }},{
            "$limit": 10
            }])))

        return results

    def get_ip_volume(self):
        def map_ips(event):
            event['label'] = event.pop('_id')
            return event

        results = map(map_ips, list(self.flow.aggregate([{
            "$match": {
                "timestamp": {
                    "$gte": datetime.datetime.utcnow() - datetime.timedelta(days=1)
                }
            }},{
            "$group": {
                "_id": "$src_ip",
                "count": {
                    "$sum": "$netflow.bytes"
                }
            }},{
            "$sort": {
              "bytes": -1
            }},{
            "$limit": 10
            }])))
        return results


    def get_dns_count(self):
        def map_dns(event):
            event['label'] = event.pop('_id')
            return event

        results = map(map_dns, list(self.dns.aggregate([{
            "$match": {
                "timestamp": {
                    "$gte": datetime.datetime.utcnow() - datetime.timedelta(days=1)
                },
                "dns.type": "answer",
                "dns.rrtype": "A"
            }},{
            "$group": {
                "_id": "$dns.rrname",
                "count": {
                    "$sum": 1
                }
            }},{
            "$sort": {
              "count": -1
            }},{
            "$limit": 10
            }])))

        return results

    def get_sensor_volume(self):
        def map_sensors(event):
            event['label'] = event.pop('_id')
            return event

        results = map(map_sensors, list(self.flow.aggregate([{
            "$match": {
                "timestamp": {
                    "$gte": datetime.datetime.utcnow() - datetime.timedelta(days=1)
                }
            }},{
            "$group": {
                "_id": "$sensor",
                "count": {
                    "$sum": "$netflow.bytes"
                }
            }},{
            "$sort": {
              "bytes": -1
            }},{
            "$limit": 10
            }])))
        return results
    
    def get_http_count(self):
        def map_http(event):
            event['label'] = event.pop('_id')
            return event

        results = map(map_http, list(self.http.aggregate([{
            "$match": {
                "timestamp": {
                    "$gte": datetime.datetime.utcnow() - datetime.timedelta(days=1)
                }
            }},{
            "$group": {
                "_id": "$http.hostname",
                "count": {
                    "$sum": 1
                }
            }},{
            "$sort": {
              "count": -1
            }},{
            "$limit": 10
            }])))

        return results

    '''Function to get the flow records for a given alert'''
    def investigate(self, IDs):
        def map_ids(ID):
            return bson.objectid.ObjectId(ID)

        def map_alerts(alerts):
            for i in range(len(alerts['timestamps'])):
                orig_alert = alerts['_id']
                if orig_alert['src_port'] is None:
                    del orig_alert['src_port']
                    del orig_alert['dest_port']

                orig_alert['timestamp'] = alerts['timestamps'][i]

                dns_times.append({
                    "timestamp": {
                        "$gte": orig_alert['timestamp'] - datetime.timedelta(minutes=5),
                        "$lte": orig_alert['timestamp'] + datetime.timedelta(minutes=5)
                    }})

                start_time = orig_alert['timestamp'] - datetime.timedelta(minutes=5)
                stop_time = orig_alert['timestamp'] + datetime.timedelta(minutes=5)

                flow_times.append({
                    "$or": [
                        { "$and": [
                            { "netflow.start": { "$gt": start_time }},
                            { "netflow.start": { "$lt": stop_time }},
                        ] },
                        { "$and": [
                            { "netflow.end": { "$gt": start_time }},
                            { "netflow.end": { "$lt": stop_time }},
                        ] },
                        { "$and": [
                            { "netflow.start": { "$lt": start_time }},
                            { "netflow.end": { "$gt": stop_time }},
                        ]}
                    ]})

                orig_alert['timestamp'] = alerts['timestamps'][i].strftime('%Y-%m-%d %H:%M:%S')

                try:
                    orig_alert['payload_printable'] = alerts['printables'][i]
                except:
                    orig_alert['payload_printable'] = False

                try:
                    decoded_packets = alerts['payloads'][i].decode('base64')
                except:
                    try:
                        decoded_packets = alerts['packets'][i].decode('base64')
                    except:
                        decoded_packets = False
                if decoded_packets:
                    hex_dump = []
                    hex_packet = ""
                    asc = ''
                    for i in range(1, len(decoded_packets), 1):
                        if 1 == i % 32:
                            hex_dump.append( hex_packet +  "     " + asc + "\n")
                            hex_packet = "%04X: " % (i-1)
                            asc = ''
                        pos = ord(decoded_packets[i-1:i])
                        hex_packet = hex_packet + "%02X " % pos
                        if pos >= 32 and pos <=126:
                            asc = asc + str(decoded_packets[i-1:i])
                        else:
                            asc = asc + "."
                    end_int = i
                    if len(hex_packet) > 0:
                        if len(decoded_packets) > 31:
                            end_int += 1
                            while 1 != end_int % 32:
                                hex_packet = hex_packet + "   "
                                end_int += 1
                        hex_dump.append(hex_packet + "     " + asc + "\n")
                    orig_alert['hex'] = hex_dump
                else:
                    orig_alert['hex'] = []

                results.append(orig_alert)

        if not isinstance(IDs, list):
            return False

        uuids = map(map_ids, IDs)

        results = []
        flow_times = []
        dns_times = []
        map(map_alerts, list(self.alerts.aggregate([{
            "$match": {
                "_id": {
                    "$in": uuids
                }
            }},{
            "$group": {
                "_id": {
                    "sensor": "$sensor",
                    "proto": "$proto",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dest_ip": "$dest_ip",
                    "dest_port": "$dest_port",
                    "signature": "$alert.signature",
                    "category": "$alert.category",
                    "severity": "$alert.severity",
                    "sid": "$alert.signature_id",
                    "rev": "$alert.rev",
                    "gid": "$alert.gid"
                },
                "printables": {
                    "$push": "$payload_printable"
                },
                "timestamps": {
                    "$push": "$timestamp"
                },
                "payloads": {
                    "$push": "$payload"
                },
                "packets": {
                    "$push": "$packet"
                }
            }}])))

        if len(results) == 0:
            return False

        try:
            flow_results = list(self.flow.aggregate([{
                "$match": {
                    "sensor": results[0]["sensor"],
                    "proto": results[0]["proto"],
                    "src_ip": results[0]["src_ip"],
                    "src_port": results[0]["src_port"],
                    "dest_ip": results[0]["dest_ip"],
                    "dest_port": results[0]["dest_port"],
                    "$or": flow_times
                }},{
                "$project": {
                    "start_time": "$netflow.start",
                    "stop_time": "$netflow.stop",
                    "sensor": "$sensor",
                    "proto": "$proto",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dest_ip": "$dest_ip",
                    "dest_port": "$dest_port",
                    "pkts": "$netflow.pkts",
                    "bytes": "$netflow.bytes",
                    "ack": "$tcp.ack",
                    "psh": "$tcp.psh",
                    "fin": "$tcp.fin",
                    "syn": "$tcp.syn"
                }},{
                "$limit": self.sizeLimit
                }]))
        except KeyError:
            flow_results = list(self.flow.aggregate([{
                "$match": {
                    "sensor": results[0]["sensor"],
                    "proto": results[0]["proto"],
                    "src_ip": results[0]["src_ip"],
                    "dest_ip": results[0]["dest_ip"],
                    "$or": event_times
                }},{
                "$project": {
                    "start_time": "$netflow.start",
                    "stop_time": "$netflow.stop",
                    "sensor": "$sensor",
                    "proto": "$proto",
                    "src_ip": "$src_ip",
                    "src_port": "$src_port",
                    "dest_ip": "$dest_ip",
                    "dest_port": "$dest_port",
                    "pkts": "$netflow.pkts",
                    "bytes": "$netflow.bytes",
                    "ack": "$tcp.ack",
                    "psh": "$tcp.psh",
                    "fin": "$tcp.fin",
                    "syn": "$tcp.syn"
                }},{
                "$limit": self.sizeLimit
                }]))

        dns_results = list(self.dns.aggregate([{
            "$match": {
                "sensor": results[0]["sensor"],
                "proto": results[0]["proto"],
                "src_ip": results[0]["src_ip"],
                "src_port": results[0]["src_port"],
                "dest_ip": results[0]["dest_ip"],
                "dest_port": results[0]["dest_port"],
                "$or": dns_times
            }},{
            "$project": {
                "timestamp": "$timestamp",
                "sensor": "$sensor",
                "proto": "$proto",
                "src_ip": "$src_ip",
                "src_port": "$src_port",
                "dest_ip": "$dest_ip",
                "dest_port": "$dest_port",
                "type": "$dns.type",
                "rrtype": "$dns.rrtype",
                "rdata": "$dns.rdata",
                "ttl": "$dns.ttl",
                "rcode": "$dns.rcode",
                "id": "$dns.id"
            }},{
            "$limit": self.sizeLimit
            }]))

        return {
            "alerts": results,
            "flow": flow_results,
            "dns": dns_results
            }
            
    #END NEW STUFF

    '''Function to close alert without any comments'''
    def close_alert_nc(self, events):

        for event in events:
            self.alerts.update( { "_id": bson.objectid.ObjectId(event) }, { "$set": { "MINERVA_STATUS": "CLOSED" }})

        return

    '''Function to close alert with comments'''
    def close_alert(self, events, comments, username):
        if comments == '':
            comments = 'NONE'

        for event in events:
            self.alerts.update( { "_id": bson.objectid.ObjectId(event) }, { "$set": { "MINERVA_STATUS": "CLOSED" }, "$push": { "MINERVA_COMMENTS": { 'USER': username, 'COMMENT': comments, 'COMMENT_TIME': datetime.datetime.utcnow() } }})

        return

    '''Function to escalate menu from console view'''
    def escalate_alert(self, events, comments, username):
        if comments == '':
            comments = 'NONE'

        for event in events:
            self.alerts.update( { "_id": bson.objectid.ObjectId(event) }, { "$set": { "MINERVA_STATUS": "ESCALATED"}, "$push": { "MINERVA_COMMENTS": { 'USER': username, 'COMMENT': comments, 'COMMENT_TIME': datetime.datetime.utcnow() } }})

        return

    '''Function to add comments to a given alert'''
    def add_comments(self, events, comments, username):
        if comments != '':
            for event in events:
                self.alerts.update({ "_id": bson.objectid.ObjectId(event) }, { "$push": { "MINERVA_COMMENTS": { 'USER': username, 'COMMENT': comments, 'COMMENT_TIME': datetime.datetime.utcnow() } }})

        return

    '''Function to get comments on a given event for the investigation page'''
    def get_comments(self, events):
        all_comments = {}
        for event in events:
            all_comments[event] = list(self.alerts.aggregate([{"$match": { "_id": bson.objectid.ObjectId(event)}},{"$project": { "MINERVA_COMMENTS": "$MINERVA_COMMENTS"}}]))

        return all_comments

    '''Function to search for Alerts for the Alert Search Menu'''
    def search_alerts(self, request, orig_search=False):
        if not orig_search:
            event_search = {}

            if len(request['src_ip']) > 0:
                event_search['src_ip'] = str(request['src_ip'])

            if len(request['src_port']) > 0:
                try:
                    event_search['src_port'] = int(request['src_port'])
                except ValueError:
                    pass

            if len(request['dest_ip']) > 0:
                event_search['dest_ip'] = str(request['dest_ip'])

            if len(request['dest_port']) > 0:
                try:
                    event_search['dest_port'] = int(request['dest_port'])
                except ValueError:
                    pass

            if len(request['sensor']) > 0:
                event_search['sensor'] = str(request['sensor'])

            if len(request['proto']) > 0:
                try:
                    proto = int(request['proto'])

                    if proto == 1:
                        event_search['proto'] = 'ICMP'

                    elif proto == 4:
                        event_search['proto'] = 'IP'

                    elif proto == 6:
                        event_search['proto'] = 'TCP'

                    elif proto == 8:
                        event_search['proto'] = 'EGP'

                    elif proto == 9:
                        event_search['proto'] = 'IGP'

                    elif proto == 17:
                        event_search['proto'] = 'UDP'

                    elif proto == 27:
                        event_search['proto'] = 'RDP'

                    elif proto == 41:
                        event_search['proto'] = 'IPv6'

                    elif proto == 51:
                        event_search['proto'] = 'AH'

                except:
                    try:
                        event_search['proto'] = str(request['proto'].upper())

                    except:
                        return 'Protocol not found'

            if len(request['sig_name']) > 0:
                event_search['alert.signature'] = request['sig_name']

            if len(request['category']) > 0:
                event_search['alert.category'] = request['category']

            if len(request['severity']) > 0:
                try:
                    event_search['alert.severity'] = int(request['severity'])
                except ValueError:
                    pass

            if len(request['sid']) > 0:
                try:
                    event_search['alert.signature_id'] = int(request['sid'])
                except ValueError:
                    pass

            if len(request['rev']) > 0:
                try:
                    event_search['alert.rev'] = int(request['rev'])
                except ValueError:
                    pass

            if len(request['gid']) > 0:
                try:
                    event_search['alert.gid'] = int(request['gid'])
                except ValueError:
                    pass

            if len(request['status']) > 0:
                event_search['MINERVA_STATUS'] = request['status']

            if len(request['start']) > 0:
                start_time = datetime.datetime.strptime(request['start'], '%m-%d-%Y %H:%M:%S')

            else:
                start_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=600)

            if len(request['stop']) > 0:
                stop_time = datetime.datetime.strptime(request['stop'], '%m-%d-%Y %H:%M:%S')

            else:
                stop_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=600)

        else:
            event_search = request
            stop_time = event_search.pop('stop_time')
            start_time = event_search.pop('start_time')

        results = self.alerts.find(
            { "$and": [
                event_search,
                { "$and": [
                    { "timestamp": { "$gt": start_time }},
                    { "timestamp": { "$lt": stop_time }},
                ]},
              ]}
            ).sort([("_id", pymongo.ASCENDING)]).limit(self.sizeLimit)

        numFound = results.count()
        results_found = map(self.map_alerts, results)

        event_search['start_time'] = start_time
        event_search['stop_time'] = stop_time

        return numFound, results_found, event_search
