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
    def __init__(self, config, log_queue):
        self.config = config
        client = pymongo.MongoClient(config['Webserver']['db']['url'],int(config['Webserver']['db']['port']))
        self.alert = client.minerva.alerts
        self.flow = client.minerva.flow
        self.log_queue = log_queue
    def insert_data(self):
        alert_events = []
        flow_events = []
        wait_time = time.time()
        count = 0
        count_max = int(self.config['Event_Receiver']['insertion_batch'])
        wait_max = int(self.config['Event_Receiver']['insertion_wait'])
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
                    alert_events.append(event)
                elif event['logType'] == 'flow':
                    event['netflow']['start_epoch'] = time.mktime(parse(event['netflow']['start']).timetuple())
                    event['netflow']['stop_epoch'] = time.mktime(parse(event['netflow']['end']).timetuple())
                    flow_events.append(event)
                count += 1
            tdiff = time.time() - wait_time
            if count >= count_max or tdiff >= wait_max:
                if len(alert_events) > 0:
                    self.alert.insert(alert_events)
                    alert_events = []
                if len(flow_events) > 0:
                    self.flow.insert(flow_events)
                    flow_events = []
                count = 0
                wait_time = time.time()
            if not self.log_queue.empty():
                continue
            else:
                time.sleep(1)
