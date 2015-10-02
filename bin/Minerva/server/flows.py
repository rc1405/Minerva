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
#import os
#from Minerva import config

class alert_flow(object):
    def __init__(self, configs):
        #db_conf = config.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')).conf['Webserver']['db']
        db_conf = configs['db']
        client = pymongo.MongoClient(db_conf['url'],int(db_conf['port']))
        if db_conf['useAuth']:
            client.minerva.authenticate(db_conf['username'], db_conf['password'])
        self.alerts = client.minerva.alerts
        self.flow = client.minerva.flow
        self.sizeLimit = configs['events']['maxResults']

    def get_flow(self, ID):
        results = self.alerts.aggregate([ { "$match": { "_id": bson.objectid.ObjectId(ID) }}, { "$project": { "document": "$$ROOT"}}])
	results_found = []
        for orig_alert in results:
            src_ip = orig_alert['document']['src_ip']
            src_port = orig_alert['document']['src_port']
            dest_ip =orig_alert['document']['dest_ip']
            dest_port = orig_alert['document']['dest_port']
            proto = orig_alert['document']['proto']
            results_found = self.flow.aggregate([ { "$match": { "src_ip": src_ip, "src_port": src_port, "dest_ip": dest_ip, "dest_port": dest_port, "proto": proto }}, { "$project": { "ID": "$_id", "document": "$$ROOT"}},{ "$sort": { "ID": 1 }}, { "$limit": self.sizeLimit }])
        return results_found, orig_alert
