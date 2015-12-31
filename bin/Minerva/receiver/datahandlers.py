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
import numpy
import netaddr
from pytz import timezone
from dateutil.parser import parse

class MongoInserter(object):
    def __init__(self, minerva_core, filter_processor):
        self.config = minerva_core.conf
        self.core = minerva_core
        #self.log_queue = log_queue
        self.filters = EventFilters(minerva_core)
        self.processor = filter_processor

    '''def insert_data(self):
        db = self.core.get_db()
        alert = db.alerts
        flow = db.flow
        dns = db.dns
        filters, checks = self.filters.get_filters()
        filter_time = time.time()
        watcher = MinervaWatchlist(self.core, method='QUEUE', log_queue=self.log_queue)
        watchlist, watch_check = watcher.get_watches()
        alert_events = []
        flow_events = []
        dns_events = []
        wait_time = time.time()
        count = 0
        count_max = int(self.config['Event_Receiver']['insertion_batch'])
        wait_max = int(self.config['Event_Receiver']['insertion_wait'])
        filter_wait = int(self.config['Event_Receiver']['filter_wait'])
        while True:
            if not self.log_queue.empty():
                event = self.log_queue.get()
                if isinstance(event, basestring):
                    try:
                        event = json.loads(event)
                    except:
                        continue
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
                    event = self.filters.process_filters(filters, checks, event)
                    alert_events.append(event)
                elif event['logType'] == 'flow':
                    try:
                        event['netflow']['start_epoch'] = time.mktime(parse(event['netflow']['start']).timetuple())
                        event['netflow']['stop_epoch'] = time.mktime(parse(event['netflow']['end']).timetuple())
                        flow_events.append(event)
                        watcher.process_watches(watchlist, watch_check, event)
                    except:
                        pass
                elif event['logType'] == 'dns':
                    timestamp = event['timestamp']
                    try:
                        ts = parse(timestamp)
                        tz = timezone('UTC')
                        event['timestamp'] = ts.astimezone(tz)
                        event['epoch'] = int(time.mktime(ts.timetuple()))
                    except:
                        pass
                    event['orig_timestamp'] = timestamp
                    dns_events.append(event)
                    watcher.process_watches(watchlist, watch_check, event)
                count += 1
            tdiff = time.time() - wait_time
            if count >= count_max or tdiff >= wait_max:
                if len(alert_events) > 0:
                    alert.insert(alert_events)
                    alert_events = []
                if len(flow_events) > 0:
                    flow.insert(flow_events)
                    flow_events = []
                if len(dns_events) > 0:
                    dns.insert(dns_events)
                    dns_events = []
                count = 0
                wait_time = time.time()
            if time.time() - filter_time >= filter_wait:
                filters, checks = self.filters.get_filters()
                filter_time = time.time()
                watchlist, watch_check = watcher.get_watches()
            if not self.log_queue.empty():
                continue
            else:
                time.sleep(1)'''

    def redis_data(self, events, filters, checks, watcher, watchlist, watch_check):
        alert_events = []
        flow_events = []
        dns_events = []
        for event in events:
            if isinstance(event, basestring):
                try:
                    event = json.loads(event)
                except:
                    continue
                if isinstance(event, basestring):
                    try:
                        event = json.loads(event)
                    except:
                        continue
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
                event = self.filters.process_filters(filters, checks, event)
                alert_events.append(event)
            elif event['logType'] == 'flow':
                try:
                    event['netflow']['start_epoch'] = time.mktime(parse(event['netflow']['start']).timetuple())
                    event['netflow']['stop_epoch'] = time.mktime(parse(event['netflow']['end']).timetuple())
                    flow_events.append(event)
                    watcher.process_watches(watchlist, watch_check, event)
                except:
                    pass
            elif event['logType'] == 'dns':
                timestamp = event['timestamp']
                try:
                    ts = parse(timestamp)
                    tz = timezone('UTC')
                    event['timestamp'] = ts.astimezone(tz)
                    event['epoch'] = int(time.mktime(ts.timetuple()))
                except:
                    pass
                event['orig_timestamp'] = timestamp
                dns_events.append(event)
                watcher.process_watches(watchlist, watch_check, event)

        return alert_events, flow_events, dns_events
    

    def insert_redis(self):
        import redis
        db = self.core.get_db()
        alert = db.alerts
        flow = db.flow
        dns = db.dns
        filters, checks = self.filters.get_filters()
        filter_time = time.time()
        wait_time = time.time()
        count_max = int(self.config['Event_Receiver']['insertion_batch'])
        wait_max = int(self.config['Event_Receiver']['insertion_wait'])
        filter_wait = int(self.config['Event_Receiver']['filter_wait'])
        r = redis.Redis(host=self.config['Event_Receiver']['redis']['server'], port=self.config['Event_Receiver']['redis']['port'])
        key = self.config['Event_Receiver']['redis']['key']
        watcher = MinervaWatchlist(self.core, method='REDIS', rd=r, key=key)
        watchlist, watch_check = watcher.get_watches()
        while True:
            pipeline = r.pipeline()
            pipeline.lrange(key, 0, count_max-1)
            pipeline.ltrim(key, count_max-1, -1)
            if r.llen(key) >= count_max or (time.time() - wait_time >= wait_max and r.llen(key) > 0):
                events = pipeline.execute()[0]
                alert_events, flow_events, dns_events = self.redis_data(events, filters, checks, watcher, watchlist, watch_check)
                if len(alert_events) > 0:
                    alert.insert(alert_events)
                if len(flow_events) > 0:
                    flow.insert(flow_events)
                if len(dns_events) > 0:
                    dns.insert(dns_events)
                wait_time = time.time()
            else:
                time.sleep(1)
            if time.time() - filter_time >= filter_wait:
                filters, checks = self.filters.get_filters()
                filter_time = time.time()
                watchlist, watch_check = watcher.get_watches()

class EventFilters(object):
    def __init__(self, minerva_core):
        self.config = minerva_core.conf
        self.core = minerva_core
        self.filters = self.reset_filters()
        self.filter_checks = self.reset_checks()

    def reset_filters(self):
        self.filters = {
            'status_CLOSED': [],
            'status_ESCALATED': [],
            'priority_1': [],
            'priority_-1': [],
            'priority_2': [],
            'priority_-2': [],
            'priority_3': [],
            'priority_-3': [],
            'priority_4': [],
            'priority_-4': [],
        }

    def reset_checks(self):
        self.filter_checks = {
            'signature': False,
            'category': False,
            'address': False,
            'session': False,
            'sig_address': False,
            'sig_session': False,
        }

    def get_sids(self, item):
        item_value =  '%i-%i-%i' % ( int(item['sig_id']), int(item['rev']), int(item['gid'] ))
        self.add_filter(item_value, item)
        self.filter_checks['signature'] = True

    def add_filter(self, item_value, item):
        if str(item['action_type']) == 'priority':
            self.filters['priority_%i' % int(item['action_value'])].append(item_value)
        elif str(item['action_type']) == 'STATUS':
            self.filters['status_%s' % str(item['action_value'])].append(item_value)

    def get_cat(self, item):
        item_value = item['category']
        self.add_filter(item_value, item)
        self.filter_checks['category'] = True

    def get_addresses(self, item):
        item_value = item['ip_address']
        self.add_filter(item_value, item)
        self.filter_checks['address'] = True

    def get_sessions(self, item):
        item_value = '%s-%s' % ( item['src_ip'], item['dest_ip'] )
        self.add_filter(item_value, item)
        self.filter_checks['session'] = True

    def get_sigAddress(self, item):
        item_value = '%i-%i-%i-%s' % (int(item['sig_id']), int(item['rev']), int(item['gid']), item['ip_address'])
        self.add_filter(item_value, item)
        self.filter_checks['sig_address'] = True

    def get_sigSession(self, item):
        item_value = '%i-%i-%i-%s-%s' % (int(item['sig_id']), int(item['rev']), int(item['gid']), item['src_ip'], item['dest_ip'])
        self.add_filter(item_value, item)
        self.filter_checks['sig_session'] = True

    def get_filters(self):
        db = self.core.get_db()
        filters = db.filters
        self.reset_filters()
        self.reset_checks()

        map(self.get_sids, list(filters.aggregate([{ "$match": { "type": "signature" }},{ "$project": { "sig_id": "$sig_id", "rev": "$rev", "gid": "$gid", "action_type": "$action_type", "action_value": "$action_value" }}])))

        map(self.get_cat, list(filters.aggregate([{ "$match": { "type": "categories" }}, { "$project": { "category": "$category", "action_type": "$action_type", "action_value": "$action_value" }}])))

        map(self.get_addresses, list(filters.aggregate([{ "$match": { "type": "address" }}, { "$project": { "ip_address": "$ip_address", "action_type": "$action_type", "action_value": "$action_value"}}])))

        map(self.get_sessions, list(filters.aggregate([{ "$match": { "type": "session" }}, { "$project": { "src_ip": "$src_ip", "dest_ip": "$dest_ip", "action_type": "$action_type", "action_value": "$action_value" }}])))

        map(self.get_sigAddress, list(filters.aggregate([{ "$match": { "type": "sig_address"}}, { "$project": { "sig_id": "$sig_id", "rev": "$rev", "gid": "$gid", "ip_address": "$ip_address", "action_type": "$action_type", "action_value": "$action_value" }}])))

        map(self.get_sigSession, list(filters.aggregate([{ "$match": { "type": "sig_session"}}, { "$project": { "sig_id": "$sig_id", "rev": "$rev", "gid": "$gid", "src_ip": "$src_ip", "dest_ip": "$dest_ip", "action_type": "$action_type", "action_value": "$action_value" }}])))

        ret_filters = {}
        for f in self.filters.keys():
            if len(self.filters[f]) > 0:
                ret_filters[f] = numpy.array(self.filters[f])
            else:
                ret_filters[f] = []
        return ret_filters, self.filter_checks


    def do_action(self, filters, event, key):
        def return_sev(sev, priority):
            sev = int(sev) + priority
            if sev > 5:
                return 5
            elif sev < 1:
                return 1
            else:
                return sev
        if key in filters['priority_1']:
            event['alert']['severity'] = return_sev(event['alert']['severity'], 1)
        elif key in filters['priority_-1']:
            event['alert']['severity'] = return_sev(event['alert']['severity'], -1)
        elif key in filters['priority_2']:
            event['alert']['severity'] = return_sev(event['alert']['severity'], 2)
        elif key in filters['priority_-2']:
            event['alert']['severity'] = return_sev(event['alert']['severity'], -2)
        elif key in filters['priority_3']:
            event['alert']['severity'] = return_sev(event['alert']['severity'], 3)
        elif key in filters['priority_-3']:
            event['alert']['severity'] = return_sev(event['alert']['severity'], -3)
        elif key in filters['priority_4']:
            event['alert']['severity'] = return_sev(event['alert']['severity'], 4)
        elif key in filters['priority_-4']:
            event['alert']['severity'] = return_sev(event['alert']['severity'], -4)
        elif key in filters['status_CLOSED']:
            event['MINERVA_STATUS'] = 'ClOSED'
        elif key in filters['status_ESCALATED']:
            event['MINERVA_STATUS'] = 'ESCALATED'
        return event
 
    def process_filters(self, filters, checks, event):
        if checks['category']:
            event = self.do_action(filters, event, event['alert']['category'])

        if checks['signature']:
            event = self.do_action(filters, event, '%i-%i-%i' % ( event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'] ))

        if checks['address']:
            event = self.do_action(filters, event, event['src_ip'])
            event = self.do_action(filters, event, event['dest_ip'])

        if checks['session']:
            event = self.do_action(filters, event, '%s-%s' % ( event['src_ip'], event['dest_ip'] ))
            event = self.do_action(filters, event, '%s-%s' % ( event['dest_ip'], event['src_ip'] ))

        if checks['sig_address']:
            event = self.do_action(filters, event, '%i-%i-%i-%s' % (event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'], event['src_ip']))
            event = self.do_action(filters, event, '%i-%i-%i-%s' % (event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'], event['dest_ip']))

        if checks['sig_session']:
            event = self.do_action(filters, event, '%i-%i-%i-%s-%s' % (event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'], event['src_ip'], event['dest_ip']))
            event = self.do_action(filters, event, '%i-%i-%i-%s-%s' % (event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'], event['dest_ip'], event['src_ip']))
  
        return event 


class MinervaWatchlist(object):
    def __init__(self, minerva_core, method=None, log_queue=None, rd=None, key=None):
        self.config = minerva_core.conf
        self.recv_id = self.config['Event_Receiver']['PCAP']['ip']
        self.core = minerva_core
        self.watches = self.reset_watches()
        self.watch_checks = self.reset_checks()
        self.method = method
        if method == 'QUEUE':
            self.log_queue = log_queue
        elif method == 'REDIS':
            self.r = rd
            self.key = key

    def reset_watches(self):
        self.watches = {
            'IP_5': [],
            'IP_4': [],
            'IP_3': [],
            'IP_2': [],
            'IP_1': [],
            'domain_5': [],
            'domain_4': [],
            'domain_3': [],
            'domain_2': [],
            'domain_1': [],
        }

    def reset_checks(self):
        self.watch_checks = {
            'IP': False,
            'domain': False,
        }

    def add_ip_watch(self, item_value, priority):
        self.watches['IP_%i' % priority].append(item_value)

    def add_domain_watch(self, item_value, priority):
        self.watches['domain_%i' % priority].append(item_value)

    def get_domains(self, item):
        self.add_domain_watch(item['domain'], int(item['priority']))
        self.watch_checks['domain'] = True

    def ip_to_str(self, item):
        return str(item)

    def get_ips(self, item):
        try:
            ipaddress = netaddr.IPNetwork(item['address'])
        except:
            return
        if ipaddress.size > 1:
            ip_addresses = map(self.ip_to_str, list(ipaddress.iter_hosts()))
            for i in ip_addresses:
                self.add_ip_watch(i, int(item['priority']))
        else:
            self.add_ip_watch(item['address'], int(item['priority']))
        self.watch_checks['IP'] = True

    def get_watches(self):
        db = self.core.get_db()
        watches = db.watchlist
        self.reset_watches()
        self.reset_checks()

        map(self.get_ips, list(watches.aggregate([{ "$match": { "type": "ip_address", "STATUS": "ENABLED" }},{ "$project": { "address": "$criteria", "priority": "$priority" }}])))

        map(self.get_domains, list(watches.aggregate([{ "$match": { "type": "domain", "STATUS": "ENABLED" }}, { "$project": { "domain": "$criteria", "priority": "$priority" }}])))


        ret_watches = {}
        for w in self.watches.keys():
            if len(self.watches[w]) > 0:
                ret_watches[w] = numpy.array(self.watches[w])
            else:
                ret_watches[w] = []
        self.reset_watches()
        return ret_watches, self.watch_checks

    def fire_alert(self, event, match, alert_type, priority):
        new_event = {
                "payload_printable" : "",
                "src_port" : event['src_port'],
                "event_type" : "alert",
                "proto" : event['proto'],
                #"timestamp" : event['timestamp'],
                "sensor": event['sensor'],
                "alert" : {
                        "category" : "minerva-watchlist",
                        "severity" : priority,
                        "rev" : 1,
                        "gid" : 999,
                        "signature" : "Minerva Watchlist %s - %s" % (alert_type, match),
                        "signature_id" : 9000000
                },
                "src_ip" : "192.168.218.9",
                "logType" : "alert",
                "packet" : "",
                "dest_ip" : event['dest_ip'],
                "dest_port" : event['dest_port'],
                #"sensor" : "receiver-%s" % self.recv_id,
                "payload" : "",
                "MINERVA_STATUS" : "OPEN",
        }
        if 'orig_timestamp' in event:
            new_event['timestamp'] = event['orig_timestamp']
        else:
            new_event['timestamp'] = event['timestamp']

        if self.method == 'QUEUE':
            self.log_queue.put(new_event)
        elif self.method == 'REDIS':
            self.r.rpush(self.key, json.dumps(new_event))

    def check_ip(self, watches, event):
        if event['src_ip'] in watches['IP_5']:
            self.fire_alert(event, event['src_ip'], 'IP', 5)
        elif event['src_ip'] in watches['IP_4']:
            self.fire_alert(event, event['src_ip'], 'IP', 4)
        elif event['src_ip'] in watches['IP_3']:
            self.fire_alert(event, event['src_ip'], 'IP', 3)
        elif event['src_ip'] in watches['IP_2']:
            self.fire_alert(event, event['src_ip'], 'IP', 2)
        elif event['src_ip'] in watches['IP_1']:
            self.fire_alert(event, event['src_ip'], 'IP', 1)

        if event['dest_ip'] in watches['IP_5']:
            self.fire_alert(event, event['dest_ip'], 'IP', 5)
        elif event['dest_ip'] in watches['IP_4']:
            self.fire_alert(event, event['dest_ip'], 'IP', 4)
        elif event['dest_ip'] in watches['IP_3']:
            self.fire_alert(event, event['dest_ip'], 'IP', 3)
        elif event['dest_ip'] in watches['IP_2']:
            self.fire_alert(event, event['dest_ip'], 'IP', 2)
        elif event['dest_ip'] in watches['IP_1']:
            self.fire_alert(event, event['dest_ip'], 'IP', 1)

    def check_domain(self, watches, event):
        if 'rdata' in event['dns']:
            if event['dns']['rdata'] in watches['domain_5']:
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 5)
                return
            elif event['dns']['rdata'] in watches['domain_4']:
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 4)
                return
            elif event['dns']['rdata'] in watches['domain_3']:
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 3)
                return
            elif event['dns']['rdata'] in watches['domain_2']:
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 2)
                return
            elif event['dns']['rdata'] in watches['domain_1']:
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 1)
                return

        #if 'rrname' in event['dns']:
            #if event['dns']['rrname'] in watches['domain_5']:
                #self.fire_alert(event, event['dns']['rrname'], 'Domain', 5)
            #elif event['dns']['rrname'] in watches['domain_4']:
                #self.fire_alert(event, event['dns']['rrname'], 'Domain', 4)
            #elif event['dns']['rrname'] in watches['domain_3']:
                #self.fire_alert(event, event['dns']['rrname'], 'Domain', 3)
            #elif event['dns']['rrname'] in watches['domain_2']:
                #self.fire_alert(event, event['dns']['rrname'], 'Domain', 2)
            #elif event['dns']['rrname'] in watches['domain_1']:
                #self.fire_alert(event, event['dns']['rrname'], 'Domain', 1)

    def process_watches(self, watches, checks, event):
        if checks['IP'] and event['logType'] == 'flow':
            self.check_ip(watches, event)
        if checks['domain'] and event['logType'] == 'dns':
            if event['dns']['type'] == 'answer':
                self.check_domain(watches, event)
