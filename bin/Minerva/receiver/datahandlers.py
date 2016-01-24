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
import uuid

import pymongo
import netaddr
import redis

from pytz import timezone
from dateutil.parser import parse

class MongoInserter(object):
    def __init__(self, minerva_core, filter_processor, process_lock):
        self.config = minerva_core.conf
        self.core = minerva_core
        self.filters = EventFilters(minerva_core)
        self.watcher = MinervaWatchlist(self.core, self.config)
        self.filter_processor = filter_processor
        self.process_lock = process_lock

    def redis_data(self, events):
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
                event = self.filters.process_filters(event)
                alert_events.append(event)
            elif event['logType'] == 'flow':
                try:
                    event['netflow']['start_epoch'] = time.mktime(parse(event['netflow']['start']).timetuple())
                    event['netflow']['stop_epoch'] = time.mktime(parse(event['netflow']['end']).timetuple())
                    flow_events.append(event)
                    self.watcher.process_watches(event)
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
                self.watcher.process_watches(event)

        return alert_events, flow_events, dns_events
    

    def insert_redis(self):
        db = self.core.get_db()
        alert = db.alerts
        flow = db.flow
        dns = db.dns
        filter_time = time.time()
        wait_time = time.time()
        count_max = int(self.config['Event_Receiver']['insertion_batch'])
        wait_max = int(self.config['Event_Receiver']['insertion_wait'])
        filter_wait = int(self.config['Event_Receiver']['filter_wait'])
        r = redis.StrictRedis(host=self.config['Event_Receiver']['redis']['server'], port=self.config['Event_Receiver']['redis']['port'])
        event_key = self.config['Event_Receiver']['redis']['event_key']
        if self.filter_processor:
            self.filters.get_filters()
            self.watcher.get_watches()
            self.process_lock.release() 
        while True:
            pipeline = r.pipeline()
            pipeline.lrange(event_key, 0, count_max-1)
            pipeline.ltrim(event_key, count_max-1, -1)
            if r.llen(event_key) >= count_max or (time.time() - wait_time >= wait_max and r.llen(event_key) > 0):
                events = pipeline.execute()[0]
                alert_events, flow_events, dns_events = self.redis_data(events)
                if len(alert_events) > 0:
                    alert.insert(alert_events)
                if len(flow_events) > 0:
                    flow.insert(flow_events)
                if len(dns_events) > 0:
                    dns.insert(dns_events)
                wait_time = time.time()
            else:
                time.sleep(1)
            if self.filter_processor:
                if time.time() - filter_time >= filter_wait:
                    self.filters.get_filters()
                    self.watcher.get_watches()
                    filter_time = time.time()

class EventFilters(object):
    def __init__(self, minerva_core):
        self.config = minerva_core.conf
        self.core = minerva_core
        self.keys = {}
        self.filter_checks = {}
        self.r = redis.StrictRedis(host=self.config['Event_Receiver']['redis']['server'], port=self.config['Event_Receiver']['redis']['port'])
        self.rkeys = {
            'priority_1': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_1']),
            'priority_-1': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_-1']),
            'priority_2': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_2']),
            'priority_-2': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_-2']),
            'priority_3': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_3']),
            'priority_-3': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_-3']),
            'priority_4': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_4']),
            'priority_-4': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_-4']),
            'priority_5': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_5']),
            'priority_-5': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'priority_-5']),
            'status_ClOSED': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'status_CLOSED']),
            'status_ESCALATED': '_'.join([self.config['Event_Receiver']['redis']['filter_key'], 'status_ESCALATED']),
        }

    def reset_keys(self):
        self.keys = {
            'priority_1': uuid.uuid4().hex,
            'priority_-1': uuid.uuid4().hex,
            'priority_2': uuid.uuid4().hex,
            'priority_-2': uuid.uuid4().hex,
            'priority_3': uuid.uuid4().hex,
            'priority_-3': uuid.uuid4().hex,
            'priority_4': uuid.uuid4().hex,
            'priority_-4': uuid.uuid4().hex,
            'priority_5': uuid.uuid4().hex,
            'priority_-5': uuid.uuid4().hex,
            'status_CLOSED': uuid.uuid4().hex,
            'status_ESCALATED': uuid.uuid4().hex,
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
        item_value =  '-'.join([str(item['sig_id']), str(item['rev']), str(item['gid'] )])
        self.add_filter(item_value, item)
        self.filter_checks['signature'] = True

    def add_filter(self, item_value, item):
        if str(item['action_type']) == 'priority':
            self.r.sadd(self.keys['priority_%i' % int(item['action_value'])], item_value)
        elif str(item['action_type']) == 'STATUS':
            self.r.sadd(self.keys['status_%s' % str(item['action_value'])], item_value)

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
        item_value = '-'.join([str(item['sig_id']), str(item['rev']), str(item['gid']), item['ip_address']])
        self.add_filter(item_value, item)
        self.filter_checks['sig_address'] = True

    def get_sigSession(self, item):
        item_value = '-'.join([str(item['sig_id']), str(item['rev']), str(item['gid']), item['src_ip'], item['dest_ip']])
        self.add_filter(item_value, item)
        self.filter_checks['sig_session'] = True

    def get_filters(self):
        db = self.core.get_db()
        filters = db.filters
        self.reset_keys()
        self.reset_checks()
        check_key = uuid.uuid4().hex

        try:
            map(self.get_sids, list(filters.aggregate([{ "$match": { "type": "signature" }},{ "$project": { "sig_id": "$sig_id", "rev": "$rev", "gid": "$gid", "action_type": "$action_type", "action_value": "$action_value" }}])))

            map(self.get_cat, list(filters.aggregate([{ "$match": { "type": "categories" }}, { "$project": { "category": "$category", "action_type": "$action_type", "action_value": "$action_value" }}])))

            map(self.get_addresses, list(filters.aggregate([{ "$match": { "type": "address" }}, { "$project": { "ip_address": "$ip_address", "action_type": "$action_type", "action_value": "$action_value"}}])))

            map(self.get_sessions, list(filters.aggregate([{ "$match": { "type": "session" }}, { "$project": { "src_ip": "$src_ip", "dest_ip": "$dest_ip", "action_type": "$action_type", "action_value": "$action_value" }}])))

            map(self.get_sigAddress, list(filters.aggregate([{ "$match": { "type": "sig_address"}}, { "$project": { "sig_id": "$sig_id", "rev": "$rev", "gid": "$gid", "ip_address": "$ip_address", "action_type": "$action_type", "action_value": "$action_value" }}])))

            map(self.get_sigSession, list(filters.aggregate([{ "$match": { "type": "sig_session"}}, { "$project": { "sig_id": "$sig_id", "rev": "$rev", "gid": "$gid", "src_ip": "$src_ip", "dest_ip": "$dest_ip", "action_type": "$action_type", "action_value": "$action_value" }}])))

            checks = []
            for k in self.keys.keys():
                size = len(self.r.smembers(self.keys[k]))
                if size == 0:
                    self.r.delete(self.keys[k])
                    r_key = '_'.join([self.config['Event_Receiver']['redis']['filter_key'], k ])
                    if r_key in self.r.keys():
                        self.r.delete(r_key)
                else:
                    self.r.rename(self.keys[k], '_'.join([self.config['Event_Receiver']['redis']['filter_key'],k]))

            for ch in self.filter_checks.keys():
                if self.filter_checks[ch]:
                    checks.append(ch)

            if len(checks) == 0:
                if self.config['Event_Receiver']['redis']['filtercheck_key'] in self.r.keys():
                    self.r.delete(self.config['Event_Receiver']['redis']['filtercheck_key'])
            else:
                for c in checks:
                    self.r.sadd(check_key, c)
                self.r.rename(check_key, self.config['Event_Receiver']['redis']['filtercheck_key'])
        except Exception as e:
            for k in self.keys.keys():
                self.r.delete(self.keys[k])
            self.r.delete(check_key)
            raise e


    def do_action(self, event, key):
        def return_sev(sev, priority):
            sev = int(sev) + priority
            if sev > 5:
                return 5
            elif sev < 1:
                return 1
            else:
                return sev
        keys = self.config['Event_Receiver']['redis']['filter_key']
        if self.r.sismember(self.rkeys['priority_1'], key):
            event['alert']['severity'] = return_sev(event['alert']['severity'], 1)
        elif self.r.sismember(self.rkeys['priority_-1'], key):
            event['alert']['severity'] = return_sev(event['alert']['severity'], -1)
        elif self.r.sismember(self.rkeys['priority_2'], key):
            event['alert']['severity'] = return_sev(event['alert']['severity'], 2)
        elif self.r.sismember(self.rkeys['priority_-2'], key):
            event['alert']['severity'] = return_sev(event['alert']['severity'], -2)
        elif self.r.sismember(self.rkeys['priority_3'], key):
            event['alert']['severity'] = return_sev(event['alert']['severity'], 3)
        elif self.r.sismember(self.rkeys['priority_-3'], key):
            event['alert']['severity'] = return_sev(event['alert']['severity'], -3)
        elif self.r.sismember(self.rkeys['priority_4'], key):
            event['alert']['severity'] = return_sev(event['alert']['severity'], 4)
        elif self.r.sismember(self.rkeys['priority_-4'], key):
            event['alert']['severity'] = return_sev(event['alert']['severity'], -4)
        elif self.r.sismember(self.rkeys['status_ClOSED'], key):
            event['MINERVA_STATUS'] = 'ClOSED'
        elif self.r.sismember(self.rkeys['status_ESCALATED'], key):
            event['MINERVA_STATUS'] = 'ESCALATED'
        return event
 
    def process_filters(self, event):
        check_key = self.config['Event_Receiver']['redis']['filtercheck_key']
        if self.r.sismember(check_key, 'category'):
            event = self.do_action(event, event['alert']['category'])

        if self.r.sismember(check_key, 'signature'):
            event = self.do_action(event, '-'.join([event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid']]))

        if self.r.sismember(check_key, 'address'):
            event = self.do_action(event, event['src_ip'])
            event = self.do_action(event, event['dest_ip'])

        if self.r.sismember(check_key, 'session'):
            event = self.do_action(event, '-'.join([ event['src_ip'], event['dest_ip']]))
            event = self.do_action(event, '-'.join([event['dest_ip'], event['src_ip'] ]))

        if self.r.sismember(check_key, 'sig_address'):
            event = self.do_action(event, '-'.join([(event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'], event['src_ip'])]))
            event = self.do_action(event, '-'.join([event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'], event['dest_ip']]))

        if self.r.sismember(check_key, 'sig_session'):
            event = self.do_action(event, '-'.join([event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'], event['src_ip'], event['dest_ip']]))
            event = self.do_action(event, '-'.join([event['alert']['signature_id'], event['alert']['rev'], event['alert']['gid'], event['dest_ip'], event['src_ip']]))
  
        return event 


class MinervaWatchlist(object):
    def __init__(self, minerva_core, key=None):
        self.config = minerva_core.conf
        self.recv_id = self.config['Event_Receiver']['PCAP']['ip']
        self.core = minerva_core
        self.watches = self.reset_watches()
        self.watch_checks = self.reset_checks()
        self.r = redis.StrictRedis(self.config['Event_Receiver']['redis']['server'], self.config['Event_Receiver']['redis']['port'])
        self.key = self.config['Event_Receiver']['redis']['event_key']
        self.keys = {
            'IP_5': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'IP_5']),
            'IP_4': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'IP_4']),
            'IP_3': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'IP_3']),
            'IP_2': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'IP_2']),
            'IP_1': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'IP_1']),
            'domain_5': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'domain_5']),
            'domain_4': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'domain_4']),
            'domain_3': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'domain_3']),
            'domain_2': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'domain_2']),
            'domain_1': '_'.join([self.config['Event_Receiver']['redis']['watchlist_key'], 'domain_1']),
        }

    def reset_watches(self):
        self.watches = {
            'IP_5': uuid.uuid4().hex,
            'IP_4': uuid.uuid4().hex,
            'IP_3': uuid.uuid4().hex,
            'IP_2': uuid.uuid4().hex,
            'IP_1': uuid.uuid4().hex,
            'domain_5': uuid.uuid4().hex,
            'domain_4': uuid.uuid4().hex,
            'domain_3': uuid.uuid4().hex,
            'domain_2': uuid.uuid4().hex,
            'domain_1': uuid.uuid4().hex,
        }

    def reset_checks(self):
        self.watch_checks = {
            'IP': False,
            'domain': False,
        }

    def add_ip_watch(self, item_value, priority):
        self.r.sadd(self.watches['IP_%i' % priority], item_value)

    def add_domain_watch(self, item_value, priority):
        self.r.sadd(self.watches['domain_%i' % priority], item_value)

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
        check_key = uuid.uuid4().hex

        try:
            map(self.get_ips, list(watches.aggregate([{ "$match": { "type": "ip_address", "STATUS": "ENABLED" }},{ "$project": { "address": "$criteria", "priority": "$priority" }}])))

            map(self.get_domains, list(watches.aggregate([{ "$match": { "type": "domain", "STATUS": "ENABLED" }}, { "$project": { "domain": "$criteria", "priority": "$priority" }}])))


            checks = []
            for k in self.watches.keys():
                size = len(self.r.smembers(self.watches[k]))
                if size == 0:
                    self.r.delete(self.watches[k])
                    r_key = '%s_%s' % ( self.config['Event_Receiver']['redis']['watchlist_key'], k )
                    if r_key in self.r.keys():
                        self.r.delete(r_key)
                else:
                    self.r.smembers(self.keys[k])
                    self.r.smembers('%s_%s' % ( self.config['Event_Receiver']['redis']['watchlist_key'], k ))
                    self.r.rename(self.watches[k], self.keys[k])

            for ch in self.watch_checks.keys():
                if self.watch_checks[ch]:
                    checks.append(ch)

            if len(checks) == 0:
                if self.config['Event_Receiver']['redis']['watchcheck_key'] in self.r.keys():
                    self.r.delete(self.config['Event_Receiver']['redis']['watchcheck_key'])
            else:
                for c in checks:
                    self.r.sadd(check_key, c)
                self.r.rename(check_key, self.config['Event_Receiver']['redis']['watchcheck_key'])
        except Exception as e:
            for k in self.watches.keys():
                self.r.delete(self.watches[k])
            self.r.delete(check_key)
            raise e


    def fire_alert(self, event, match, alert_type, priority):
        new_event = {
                "payload_printable" : "",
                "src_port" : event['src_port'],
                "event_type" : "alert",
                "proto" : event['proto'],
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
                "payload" : "",
                "MINERVA_STATUS" : "OPEN",
        }
        if 'orig_timestamp' in event:
            new_event['timestamp'] = event['orig_timestamp']
        else:
            new_event['timestamp'] = event['timestamp']

        self.r.rpush(self.key, json.dumps(new_event))

    def check_ip(self, event):
        if self.r.sismember(self.keys['IP_5'], event['src_ip']):
            self.fire_alert(event, event['src_ip'], 'IP', 5)
        elif self.r.sismember(self.keys['IP_4'], event['src_ip']):
            self.fire_alert(event, event['src_ip'], 'IP', 4)
        elif self.r.sismember(self.keys['IP_3'], event['src_ip']):
            self.fire_alert(event, event['src_ip'], 'IP', 3)
        elif self.r.sismember(self.keys['IP_2'], event['src_ip']):
            self.fire_alert(event, event['src_ip'], 'IP', 2)
        elif self.r.sismember(self.keys['IP_1'], event['src_ip']):
            self.fire_alert(event, event['src_ip'], 'IP', 1)

        if self.r.sismember(self.keys['IP_5'], event['dest_ip']):
            self.fire_alert(event, event['dest_ip'], 'IP', 5)
        elif self.r.sismember(self.keys['IP_4'], event['dest_ip']):
            self.fire_alert(event, event['dest_ip'], 'IP', 4)
        elif self.r.sismember(self.keys['IP_3'], event['dest_ip']):
            self.fire_alert(event, event['dest_ip'], 'IP', 3)
        elif self.r.sismember(self.keys['IP_2'], event['dest_ip']):
            self.fire_alert(event, event['dest_ip'], 'IP', 2)
        elif self.r.sismember(self.keys['IP_1'], event['dest_ip']):
            self.fire_alert(event, event['dest_ip'], 'IP', 1)

    def check_domain(self, event):
        if 'rdata' in event['dns']:
            if self.r.sismember(self.keys['domain_5'], event['dns']['rdata']):
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 5)
            elif self.r.sismember(self.keys['domain_4'], event['dns']['rdata']):
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 4)
            elif self.r.sismember(self.keys['domain_3'], event['dns']['rdata']):
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 3)
            elif self.r.sismember(self.keys['domain_2'], event['dns']['rdata']):
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 2)
            elif self.r.sismember(self.keys['domain_1'], event['dns']['rdata']):
                self.fire_alert(event, event['dns']['rdata'], 'Domain', 1)

    def process_watches(self, event):
        watch_key = self.config['Event_Receiver']['redis']['watchcheck_key']
        if self.r.sismember(watch_key, 'IP') and event['logType'] == 'flow':
            self.check_ip(event)
        if self.r.sismember(watch_key, 'domain') and event['logType'] == 'dns':
            if event['dns']['type'] == 'answer':
                self.check_domain(event)
