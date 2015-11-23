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

class event_filters(object):
    '''Setup Initial Parameters'''
    def __init__(self, minerva_core):
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']
        db = minerva_core.get_db()
        self.filters = db.filters
        self.alerts = db.alerts
        self.flow = db.flow
        self.sessions = db.sessions


    def map_filters(self, item):
        item['sig_id'] = int(item['sig_id'])
        item['rev'] = int(item['rev'])
        item['gid'] = int(item['gid'])
        if item['action_type'] == 'priority':
            item['action_value'] = int(item['action_value'])
        return item

    '''Function to gather event filters'''
    def get_filters(self):

        items_found = map(self.map_filters, list(self.filters.aggregate([{ "$match": {}}, {"$project": { "ID": "$_id", "creation_time": "$creation_time", "type": "$type", "sig_id": "$sig_id", "rev": "$rev", "gid": "$gid", "category": "$category", "ip_address": "$ip_address", "src_ip": "$src_ip", "dest_ip": "$dest_ip", "action_type": "$action_type", "action_value": "$action_value", "STATUS": "$STATUS"}},{ "$limit": self.sizeLimit }])))

        return len(items_found), items_found

    def add_filter(self, request):
        items = ['sig_id','rev','gid','category','ip_address','src_ip','dest_ip','action_type','action_value']
        for i in items:
            if not i in request.keys():
                request[i] = ''
        if request['action_type'] == 'priority':
            if request['priority_op'] == 'increase':
                request['action_value'] = int(request['action_value'])
            elif request['priority_op'] == 'decrease':
                request['action_value'] = 0 - int(request['action_value'])
        print(request['action_value'])
        self.filters.insert({
               "type": request['type'],
               "sig_id": request['sig_id'],
               "rev": request['rev'],
               "gid": request['gid'],
               "category": request['category'],
               "ip_address": request['ip_address'],
               "src_ip": request['src_ip'],
               "dest_ip": request['dest_ip'],
               "action_type": request['action_type'],
               "action_value": request['action_value'],
               "STATUS": 'temporary',
               "creation_time": datetime.datetime.utcnow(),
        })

    '''Function to keep or delete an event filter'''
    def change_filter(self, events, action):
        for event in events:
            if action == 'delete':
                self.filters.remove({"_id": bson.objectid.ObjectId(event)})
            elif action == 'keep':
                self.filters.update({"_id": bson.objectid.ObjectId(event) }, { "$set": { "STATUS": "permanent" }})
        return

    '''Function to mass change alerts'''
    def change_alerts(self, request, username):
        search = {}
        if request['action_type'] == 'STATUS':
            change = { "$set": { "MINERVA_STATUS": str(request['action_value'])}, "$push": { "MINERVA_COMMENTS": { 'USER': username, 'COMMENT': 'Mass Change.  Status changed to %s' % str(request['action_value']), 'COMMENT_TIME': datetime.datetime.utcnow() }}}
        elif request['action_type'] == 'priority':
            if request['priority_op'] == 'increase':
                delta = int(request['action_value'])
            else:
                delta = 0 - int(request['action_value'])
            print(delta)
            change = { "$inc": { "alert.severity": delta },"$push": { "MINERVA_COMMENTS": { 'USER': username, 'COMMENT': 'Mass Change.  Priority changed by %i' % delta, 'COMMENT_TIME': datetime.datetime.utcnow() }}}
        if 'ApplyTo' in request.keys():
            if request['ApplyTo'] == 'OPEN':
                search['MINERVA_STATUS'] = 'OPEN'
            if request['ApplyTo'] == 'ESCALATED':
                search['MINERVA_STATUS'] = 'ESCALATED'
            if request['ApplyTo'] == 'NOT_CLOSED':
                search['MINERVA_STATUS'] = { "$in": ['OPEN', 'ESCALATED']}
            if request['ApplyTo'] == 'ClOSED':
                search['MINERVA_STATUS'] = 'ClOSED'
        if request['type'] in ['signature', 'sig_session', 'sig_address']:
            search['alert.signature_id'] = int(request['sig_id'])
            search['alert.rev'] = int(request['rev'])
            search['alert.gid'] = int(request['gid'])
        if request['type'] in ['address', 'sig_address']:
            search['$or'] = []
            search['$or'].append({"src_ip": request['ip_address']})
            search['$or'].append({"dest_ip": request['ip_address']})
        elif request['type'] in ['session', 'sig_session']:
            search['$or'] = []
            search['$or'].append({"src_ip": request['src_ip'], "dest_ip": request['dest_ip']})
            search['$or'].append({"src_ip": request['dest_ip'], "dest_ip": request['src_ip']})
        if request['type'] == 'category':
            search['alert.category'] = request['category'] 
        self.alerts.update_many(search,change)
        if request['action_type'] == 'priority':
            self.alerts.update_many({"alert.severity": { "$gt": 5 }}, { "$set": { "alert.severity": 5 }})
            self.alerts.update_many({"alert.severity": { "$lt": 1 }}, { "$set": { "alert.severity": 1 }})

        return

