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

import bson
import time

import pymongo

class sensors(object):
    def __init__(self, minerva_core):
        db = minerva_core.get_db()
        self.collection = db.certs
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']

    def map_sensors(self, sensor):
        ID = sensor.pop('_id')
        sensor['ID'] = ID
        return sensor

    def get_sensors(self):
        items_found = map(self.map_sensors, self.collection.find({
            "type": "sensor"
        }).sort([(
            "STATUS", 
            pymongo.DESCENDING
        )]).limit(self.sizeLimit))

        return items_found
    def update(self, sensors, action):
        for s in sensors:
            if str(action) == 'enable':
                status = 'APPROVED'
            else:
                status = '_DENIED'
            self.collection.update({ 
                "_id": bson.objectid.ObjectId(s)
                },{ 
                "$set" : { 
                    "timestamp": time.time(), 
                    "STATUS": status 
                }})
