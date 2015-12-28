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
import bson

import pymongo

class alert_console(object):
    '''Setup Initial Parameters'''
    def __init__(self, minerva_core):
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']
        db = minerva_core.get_db()
        self.alerts = db.alerts
        self.flow = db.flow
        self.sessions = db.sessions

    def map_alerts(self, item):
        ret_dict = {}
        ret_dict['ID'] = item.pop('_id')
        ret_dict['epoch'] = item.pop('epoch')
        ret_dict['document'] = item
        return ret_dict

    '''Function to gather alerts to present to console'''
    def get_alerts(self):
        results = self.alerts.find({"MINERVA_STATUS": "OPEN"}).sort([("alert.severity", pymongo.DESCENDING),("timestamp", pymongo.ASCENDING)]).limit(self.sizeLimit)
        numFound = results.count()
        items_found = map(self.map_alerts, results)

        return numFound, items_found

    '''Function to gather alerts to present to the escalation view'''
    def get_escalated_alerts(self):

        results = self.alerts.find({"MINERVA_STATUS": "ESCALATED"}).sort([("alert.severity", pymongo.DESCENDING),("timestamp", pymongo.ASCENDING)]).limit(self.sizeLimit)
        numFound = results.count()
        items_found = map(self.map_alerts, results)

        return numFound, items_found

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

        '''results_found = self.alerts.aggregate([ { "$match":
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
            ])'''

        results = self.alerts.find(
            { "$and": [
                event_search,
                { "$and": [
                    { "epoch": { "$gt": start_epoch }},
                    { "epoch": { "$lt": stop_epoch }},
                ]},
              ]}
            ).sort([("_id", pymongo.ASCENDING)]).limit(self.sizeLimit)

        numFound = results.count()
        results_found = map(self.map_alerts, results)

        event_search['start_epoch'] = start_epoch
        event_search['stop_epoch'] = stop_epoch

        return numFound, results_found, event_search
