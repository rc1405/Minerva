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
import re

import pymongo
import netaddr
import zmq

class watchlist(object):
    '''Setup Initial Parameters'''
    def __init__(self, minerva_core):
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']
        db = minerva_core.get_db()
        self.watchlist = db.watchlist
        self.flow = db.flow

    def send_update_to_receiver(self):
        context = zmq.Context()
        sender = context.socket(zmq.DEALER)
        receivers = {}


        #for r in self.db.search.for.receivers['receivers']:
            #receivers[r] = context.socket(zmq.DEALER)
            #ip, recv_port, sub_port = r.split('_')
            #sender.connect('tcp://%s:%s' % (ip, recv_port))
            #receiver.connect('tcp://%s:%s' % (ip, sub_port))

        sender.send_json({
            "_function": "auth",
            "_cert": self.PUBCERT
        })
        msg = sender.recv_json()
        server_cert = M2Crypto.X509.load_cert_string(str(msg['_cert']))
        pub_key = server_cert.get_pubkey()
        rsa_key = pub_key.get_rsa()
        self.SRVKEY = rsa_key
        AESKEY = self._decrypt_rsa(msg['_message'])
        if AESKEY:
            self.AESKEY = AESKEY.decode('base64')


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
                   "tag": request['tag'],
                   "STATUS": 'ENABLED',
                   "date_created": datetime.datetime.utcnow(),
                   "date_changed": datetime.datetime.utcnow(),
            })
            return 'Success'
        else:
            return 'Watchlist item %s already exists' % request['criteria']

    def add_watchlist_file(self, request):
        added = 0
        duplicate = 0
        failed = 0
        inactive = re.compile(r'(?P<comment>^\s+#|#)')
        addr = re.compile(r'(?P<addr>\d+.\d+.\d+.\d+/\d+|\d+.\d+.\d+.\d+)')
        if request['disable_old'] == 'on':
            self.watchlist.update({ "type": request['type'], "tag": request['tag']},{ "$set": { "STATUS": "DISABLED"}}, multi=True)

        current_count = self.watchlist.find({ "type": request['type'], "tag": request['tag']}).count()
        batch = []

        for row in request['watchlist_file'].file.readlines():
            watch = False
            comments = inactive.findall(row)
            if len(comments) > 0:
                status = 'DISABLED'
            else:
                status = 'ENABLED'
            if request['type'] == 'ip_address':
                addresses = addr.findall(row)
                if len(addresses) > 0:
                    try:
                        ipaddress = netaddr.IPNetwork(addresses[0])
                        criteria = addresses[0]
                        watch = True
                    except:
                        failed += 1
                        continue
            elif request['type'] == 'domain':
                if len(row.strip('#').strip()) > 0:
                    criteria = row.strip()
                    watch = True
            if watch:
                if current_count == 0:
                    batch.append({
                           "type": request['type'],
                           "criteria": criteria,
                           "priority": int(request['priority']),
                           "tag": request['tag'],
                           "STATUS": status,
                           "date_changed": datetime.datetime.utcnow(),
                           "date_updated": datetime.datetime.utcnow(),
                    })
                    added += 1
                    if len(batch) >= self.sizeLimit:
                        self.watchlist.insert(batch)
                        batch = []
                else:
                    results = self.watchlist.find({"criteria": criteria, "type": request['type'], "tag": { "$nin": [request['tag']]}}).count()
                    if results == 0:
                        self.watchlist.update(
                           {
                               "type": request['type'],
                               "criteria": criteria,
                           },
                           { "$set": { 
                               "type": request['type'],
                               "criteria": criteria,
                               "priority": int(request['priority']),
                               "tag": request['tag'],
                               "STATUS": status,
                               "date_changed": datetime.datetime.utcnow(),
                        }},upsert=True)
                        added += 1
                    else:
                        duplicate += 1

        if current_count == 0:
            if len(batch) > 0:
                self.watchlist.insert(batch)
        else:
            self.watchlist.update({ "date_created": { "$exists": False}},{ "$set": { "date_updated": datetime.datetime.utcnow()}}, upsert=True, multi=True)

        return '%i items added, %i items failed, %i were duplicated' % (added, failed, duplicate)
                
            

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
