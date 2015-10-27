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
import time
#import os
#from Minerva import config

class sensors(object):
    def __init__(self, configs):
        #db_conf = config.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')).conf['Webserver']['db']
        db_conf = configs['db']
        client = pymongo.MongoClient(db_conf['url'],int(db_conf['port']))
        if db_conf['useAuth']:
            client.minerva.authenticate(db_conf['username'], db_conf['password'])
        self.collection = client.minerva.sensors
        self.sizeLimit = configs['events']['maxResults']

    def get_sensors(self):
        items_found = self.collection.aggregate([{ "$match": { "STATUS": { "$in": ["NOT_APPROVED","CERT_CHANGED","APPROVED","_DENIED","RECEIVER_CHANGED","IP_CHANGED"]} } }, { "$project": { "ID": "$_id", "STATUS": "$STATUS", "document": "$$ROOT" }},{ "$sort": { "STATUS": -1 }},{ "$limit": self.sizeLimit } ] )
        return items_found
    def update(self, sensors, action):
        for s in sensors:
            if str(action) == 'enable':
                status = 'APPROVED'
            else:
                status = '_DENIED'
            self.collection.update({ "_id": bson.objectid.ObjectId(s)}, { "$set" : { "timestamp": time.time(), "STATUS": status }})
