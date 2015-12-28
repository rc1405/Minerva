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
import netaddr

class watchlist(object):
    '''Setup Initial Parameters'''
    def __init__(self, minerva_core):
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']
        db = minerva_core.get_db()
        self.watchlist = db.watchlist
        self.flow = db.flow

    def map_watchlist(self, item):
        ID = item.pop('_id')
        item['ID'] = ID
        return item

    '''Function to gather watchlist items'''
    def get_watchlist(self):

        results = self.watchlist.find({}).sort([("STATUS", pymongo.DESCENDING),("date_created", pymongo.DESCENDING)]).limit(self.sizeLimit)
        numFound = results.count()
        items_found = map(self.map_watchlist, results)

        return numFound, items_found

    def add_watchlist(self, request):
        if request['type'] == 'ip_address':
            try:
                ipaddress = netaddr.IPNetwork(request['criteria'])
            except:
                return 'Invalid IP Address or CIDR Range'
        elif request['type'] == 'domain':
            if len(str(request['criteria'])) == 0:
                return 'No Domain Entered'
        results = self.watchlist.find({"criteria": request['criteria'], "type": request['type']}).count()
        if results == 0:
            self.watchlist.insert({
                   "type": request['type'],
                   "criteria": request['criteria'],
                   "priority": int(request['priority']),
                   "STATUS": 'ENABLED',
                   "date_created": datetime.datetime.utcnow(),
                   "date_changed": datetime.datetime.utcnow(),
            })
            return 'Success'
        else:
            return 'Watchlist item %s already exists' % request['criteria']

    '''Function to Enable/Disable or delete a watchlist item'''
    def change_watchlist(self, request):
        for event in request['events']:
            if request['req_type'] == 'delete':
                self.watchlist.remove({"_id": bson.objectid.ObjectId(event)})
            elif request['req_type'] == 'status_toggle':
                current_status = self.watchlist.find({"_id": bson.objectid.ObjectId(event) })
                if current_status.count() > 0:
                    current_status = list(current_status)[0]['STATUS']
                    if current_status == 'ENABLED':
                        self.watchlist.update({"_id": bson.objectid.ObjectId(event) }, { "$set": { "STATUS": "DISABLED", "date_changed": datetime.datetime.utcnow() }})
                    else:
                        self.watchlist.update({"_id": bson.objectid.ObjectId(event) }, { "$set": { "STATUS": "ENABLED", "date_changed": datetime.datetime.utcnow() }})
        return 

    '''
    def change_alerts(self, request, username):
        search = {}
        if request['action_type'] == 'STATUS':
            change = { "$set": { "MINERVA_STATUS": str(request['action_value'])}, "$push": { "MINERVA_COMMENTS": { 'USER': username, 'COMMENT': 'Mass Change.  Status changed to %s' % str(request['action_value']), 'COMMENT_TIME': datetime.datetime.utcnow() }}}
        elif request['action_type'] == 'priority':
            if request['priority_op'] == 'increase':
                delta = int(request['action_value'])
            else:
                if int(request['action_value']) < 0:
                    delta = request['action_value']
                else:
                    delta = 0 - int(request['action_value'])
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

        return'''

