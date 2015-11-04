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

import pymongo
import bson
import collections
import time
#import os
#from Minerva import config
class alert_console(object):
    def __init__(self, configs):
        #db_conf = config.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')).conf['Webserver']['db']
        db_conf = configs['db']
        self.sizeLimit = configs['events']['maxResults']
        client = pymongo.MongoClient(db_conf['url'],int(db_conf['port']))
        if db_conf['useAuth']:
            client.minerva.authenticate(db_conf['username'], db_conf['password'])
        self.alerts = client.minerva.alerts
        self.flow = client.minerva.flow
        self.sessions = client.minerva.sessions
    def convert(self, data):
        if isinstance(data, basestring):
            return str(data)
        elif isinstance(data, collections.Mapping):
            return dict(map(self.convert, data.iteritems()))
        elif isinstance(data, collections.Iterable):
            return type(data)(map(self.convert, data))
        else:
            return data
    def get_alerts(self):
        #items_found = self.alerts.aggregate([{ "$match": { "MINERVA_STATUS":  "OPEN" } }, { "$project": { "ID": "$_id", "severity": "$alert.severity", "epoch": "$epoch", "document": {"timestamp": "$timestamp", "src_ip": "$src_ip", "src_port": "$src_port", "proto": "$proto", "alert": { "signature": "$alert.signature", "category": "$alert.category", "severity": "$alert.severity", "signature_id": "$alert.signature_id", "rev": "$alert.rev", "gid": "$alert.gid"}, "sensor": "$sensor", "dest_ip": "$dest_ip", "dest_port": "$dest_port" }}},{ "$sort": { "severity": -1, "epoch": 1 }},{ "$limit": self.sizeLimit } ] )
        items_found = self.alerts.aggregate([{ "$match": { "MINERVA_STATUS":  "OPEN" } },{ "$sort": { "severity": -1, "epoch": 1 }},{ "$limit": self.sizeLimit }, { "$project": { "ID": "$_id", "severity": "$alert.severity", "epoch": "$epoch", "document": {"timestamp": "$timestamp", "src_ip": "$src_ip", "src_port": "$src_port", "proto": "$proto", "alert": { "signature": "$alert.signature", "category": "$alert.category", "severity": "$alert.severity", "signature_id": "$alert.signature_id", "rev": "$alert.rev", "gid": "$alert.gid"}, "sensor": "$sensor", "dest_ip": "$dest_ip", "dest_port": "$dest_port" }}} ] )
        results = self.alerts.aggregate([{ "$match": { "MINERVA_STATUS": "OPEN" }},{ "$group": { "_id": "$null", "count": { "$sum": 1 }}}] )
        numFound = 0
        for i in results:
            numFound = i['count']
        return numFound, items_found
    def get_escalated_alerts(self):
        items_found = self.alerts.aggregate([{ "$match": { "MINERVA_STATUS":  "ESCALATED" } }, { "$project": { "ID": "$_id", "severity": "$alert.severity", "epoch": "$epoch", "document": {"timestamp": "$timestamp", "src_ip": "$src_ip", "src_port": "$src_port", "proto": "$proto", "alert": { "signature": "$alert.signature", "category": "$alert.category", "severity": "$alert.severity", "signature_id": "$alert.signature_id", "rev": "$alert.rev", "gid": "$alert.gid"}, "sensor": "$sensor", "dest_ip": "$dest_ip", "dest_port": "$dest_port" }}},{ "$sort": { "severity": -1, "epoch": 1 }},{ "$limit": self.sizeLimit } ] )
        results = self.alerts.aggregate([{ "$match": { "MINERVA_STATUS": "ESCALATED" }},{ "$group": { "_id": "$null", "count": { "$sum": 1 }}}] )
        numFound = 0
        for i in results:
            numFound = i['count']
        return numFound, items_found
    def close_alert_nc(self, events):
        #for event in events.split(','):
        for event in events:
            self.alerts.update( { "_id": bson.objectid.ObjectId(event) }, { "$set": { "MINERVA_STATUS": "CLOSED" }, "$push": { "MINERVA_COMMENTS": "NONE" }})
        return
    def close_alert(self, events, comments):
        if comments == '':
            comments = 'NONE'
        #for event in events.split(','):
        for event in events:
            self.alerts.update( { "_id": bson.objectid.ObjectId(event) }, { "$set": { "MINERVA_STATUS": "CLOSED" }, "$push": { "MINERVA_COMMENTS": comments }})
        return
    def escalate_alert(self, events, comments):
        if comments == '':
            comments = 'NONE'
        #for event in events.split(','):
        for event in events:
            self.alerts.update( { "_id": bson.objectid.ObjectId(event) }, { "$set": { "MINERVA_STATUS": "ESCALATED"}, "$push": { "MINERVA_COMMENTS": comments }})
        return
    def add_comments(self, events, comments):
        if comments != '':
            # for event in events.split(','):
            for event in events:
                self.alerts.update({ "_id": bson.objectid.ObjectId(event) }, { "$push": { "MINERVA_COMMENTS": comments }})
        return
    def search_alerts(self, request, orig_search=False):
        if not orig_search:
            event_search = {}
            if len(request['src_ip']) > 0:
                event_search['src_ip'] = str(request['src_ip'])
            if len(request['src_port']) > 0:
                event_search['src_port'] = int(request['src_port'])
            if len(request['dest_ip']) > 0:
                event_search['dest_ip'] = str(request['dest_ip'])
            if len(request['dest_port']) > 0:
                event_search['dest_port'] = int(request['dest_port'])
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
                event_search['alert.severity'] = int(request['severity'])
            if len(request['sid']) > 0:
                event_search['alert.signature_id'] = int(request['sid'])
            if len(request['rev']) > 0:
                event_search['alert.rev'] = int(request['rev'])
            if len(request['gid']) > 0:
                event_search['alert.gid'] = int(request['gid'])
            if len(request['status']) > 0:
                event_search['MINERVA_STATUS'] = request['status']
            if len(request['start']) > 0:
                start_epoch = time.mktime(time.strptime(request['start'], '%m-%d-%Y %H:%M:%S'))
            else:
                start_epoch = 0
            if len(request['stop']) > 0:
                stop_epoch = time.mktime(time.strptime(request['stop'], '%m-%d-%Y %H:%M:%S'))
            else:
                stop_epoch = 0
            if start_epoch == 0 and stop_epoch == 0:
                start_epoch = time.time() - 600
                stop_epoch = time.time()
            elif start_epoch == 0 and stop_epoch > 0:
                start_epoch = stop_epoch - 600
            elif start_epoch > 0 and stop_epoch == 0:
                if (start_epoch + 600) > time.time():
                    stop_epoch = time.time()
                else:
                    stop_epoch = start_epoch + 600
        else:
            event_search = request
            stop_epoch = event_search.pop('stop_epoch')
            start_epoch = event_search.pop('start_epoch')

        results_found = self.alerts.aggregate([ { "$match":
            { "$and": [
                event_search,
                    { "$and": [
                        { "epoch": { "$gt": start_epoch }},
                        { "epoch": { "$lt": stop_epoch }},
                    ] },
                ]}
            },
            { "$project": { 
                "ID": "$_id", 
                "severity": "$alert.severity", 
                "epoch": "$epoch", 
                "document": {
                    "timestamp": "$timestamp", 
                    "src_ip": "$src_ip", 
                    "src_port": "$src_port", 
                    "proto": "$proto", 
                    "alert": { 
                        "signature": "$alert.signature", 
                        "category": "$alert.category", 
                        "severity": "$alert.severity", 
                        "signature_id": "$alert.signature_id", 
                        "rev": "$alert.rev", 
                        "gid": "$alert.gid"
                    }, 
                    "sensor": "$sensor", 
                    "dest_ip": "$dest_ip", 
                    "dest_port": "$dest_port",
                    "MINERVA_STATUS": "$MINERVA_STATUS"
                    }
                }
            },
            { "$sort": { 
                "ID": 1 
                }
            }, 
            { "$limit": self.sizeLimit }
            ])

        event_search['start_epoch'] = start_epoch
        event_search['stop_epoch'] = stop_epoch

        return results_found, event_search
