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


import time
import json

import pymongo
from pytz import timezone
from dateutil.parser import parse

class MongoInserter(object):
    def __init__(self, minerva_core, log_queue):
        self.config = minerva_core.conf
        self.core = minerva_core
        self.log_queue = log_queue

    def insert_data(self):
        db = self.core.get_db()
        alert = db.alerts
        flow = db.flow
        filters = self.get_filters()
        filter_time = time.time()
        alert_events = []
        flow_events = []
        wait_time = time.time()
        count = 0
        count_max = int(self.config['Event_Receiver']['insertion_batch'])
        wait_max = int(self.config['Event_Receiver']['insertion_wait'])
        filter_wait = int(self.config['Event_Receiver']['filter_wait'])
        while True:
            if not self.log_queue.empty():
                event = json.loads(self.log_queue.get())
                if event['logType'] == 'alert':
                    timestamp = event['timestamp']
                    try:
                        ts = parse(timestamp)
                        tz = timezone('UTC')
                        event['timestamp'] = ts.astimezone(tz)
                        event['epoch'] = int(time.mktime(ts.timetuple()))
                    except:
                        pass
                    event['orig_timestamp'] = timestamp
                    event = self.process_filters(filters, event)
                    alert_events.append(event)
                elif event['logType'] == 'flow':
                    event['netflow']['start_epoch'] = time.mktime(parse(event['netflow']['start']).timetuple())
                    event['netflow']['stop_epoch'] = time.mktime(parse(event['netflow']['end']).timetuple())
                    flow_events.append(event)
                count += 1
            tdiff = time.time() - wait_time
            if count >= count_max or tdiff >= wait_max:
                if len(alert_events) > 0:
                    alert.insert(alert_events)
                    alert_events = []
                if len(flow_events) > 0:
                    flow.insert(flow_events)
                    flow_events = []
                count = 0
                wait_time = time.time()
            if time.time() - filter_time >= filter_wait:
                filters = self.get_filters()
                filter_time = time.time()
            if not self.log_queue.empty():
                continue
            else:
                time.sleep(1)
    def get_sids(self, item):
        return '%i-%i-%i' % ( item['sig_id'], item['rev'], item['gid'] )

    def get_cat(self, item):
        return item['category']

    def get_addresses(self, item):
        return item['ip_address']

    def get_sessions(self, item):
        return '%s-%s' % ( item['src_ip'], item['dest_ip'] )

    def map_actions(self, item):
        if item['type'] == 'category':
            return item['category_name'], item['action_type'], item['action_value']
        if item['type'] == 'signature':
            return '%i-%i-%i' % (item['sig_id'],item['rev'],item['gid']), item['action_type'], item['action_value']
        if item['type'] == 'address':
            return item['ip_address'], item['action_type'], item['action_value']
        if item['type'] == 'session':
            return '%s-%s' % (item['src_ip'],item['dest_ip']), item['action_type'], item['action_value']
        return output

    def get_actions(self, items):
        ret_actions = {}
        for a in items:
            ret_actions[a[0]] = [a[1], a[2]]
        return ret_actions

    def get_filters(self):
        db = self.core.get_db()
        filters = db.filters
        all_filters = {}
        all_filters['signatures'] = map(self.get_sids, list(filters.aggregate([{ "$match": { "type": "signature" }},{ "$project": { "sig_id": "$sig_id", "rev": "$rev", "gid": "$gid" }}])))
        all_filters['categories'] = map(self.get_cat, list(filters.aggregate([{ "$match": { "type": "categories" }}, { "$project": { "category": "$category"}}])))
        all_filters['addresses'] = map(self.get_addresses, list(filters.aggregate([{ "$match": { "type": "address" }}, { "$project": { "ip_address": "$ip_address"}}])))
        all_filters['session'] = map(self.get_sessions, list(filters.aggregate([{ "$match": { "type": "session" }}, { "$project": { "src_ip": "$src_ip", "dest_ip": "$dest_ip"}}])))
        all_filters['actions'] = self.get_actions(map(self.map_actions, list(filters.find())))
        return all_filters

    def do_action(self, filters, event, key):
        action = filters['actions'][key]
        if str(action[0]) == 'priority':
            sev = int(event['alert']['severity']) + int(action[1])
            if sev > 5:
                sev = 5
            if sev < 1:
                sev = 1
            event['alert']['severity'] = sev
            return event
        if str(action[0]) == 'STATUS':
            event['MINERVA_STATUS'] = action[1]
            return event
 
    def process_filters(self, filters, event):
        if len(filters['categories']) > 0:
            if event['alert']['category'] in filters['categories']:
                event = self.do_action(filters, event, event['alert']['category'])

        if len(filters['signatures']) > 0:
            if '%i-%i-%i' % ( event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'] ) in filters['signatures']:
                event = self.do_action(filters, event, '%i-%i-%i' % ( event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'] ))

        if len(filters['addresses']) > 0:
            if event['src_ip'] in filters['addresses']:
                event = self.do_action(filters, event, event['src_ip'])
            if event['dest_ip'] in filters['addresses']:
                event = self.do_action(filters, event, event['dest_ip'])

        if len(filters['session']) > 0:
            if '%s-%s' % ( event['src_ip'], event['dest-ip'] ) in filters['session']:
                event = self.do_action(filters, event, '%s-%s' % ( event['src_ip'], event['dest-ip'] ))
            elif '%s-%s' ( event['dest_ip'], event['src_ip'] ) in filters['session']:
                event = self.do_action(filters, event, '%s-%s' ( event['dest_ip'], event['src_ip'] ))
  
        return event 
