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

class dns(object):

    '''Initialize Class'''
    def __init__(self, minerva_core):
        db = minerva_core.get_db()
        self.alerts = db.alerts
        self.flow = db.flow
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']

    '''Function to get the flow records for a given alert'''
    def get_flow(self, IDs):
        results_found = []

        for ID in IDs:
            results = self.alerts.aggregate([ { "$match": { "_id": bson.objectid.ObjectId(ID) }}, { "$project": { "document": "$$ROOT"}}])
            flow_results = []

            for orig_alert in results:
                src_ip = orig_alert['document']['src_ip']
                src_port = orig_alert['document']['src_port']
                dest_ip =orig_alert['document']['dest_ip']
                dest_port = orig_alert['document']['dest_port']
                proto = orig_alert['document']['proto']
                epoch = orig_alert['document']['epoch']
                start_epoch = int(epoch) - 300
                stop_epoch = int(epoch) + 300
                flow_results = self.flow.aggregate([ { "$match": 
                        { "$and": [
                        { "src_ip": src_ip, "src_port": src_port, "dest_ip": dest_ip, "dest_port": dest_port, "proto": proto },
                        { "$or": [
                        { "$and": [
                        { "netflow.start_epoch": { "$gt": start_epoch }},
                        { "netflow.start_epoch": { "$lt": stop_epoch }},
                        ] },
                        { "$and": [
                        {"netflow.stop_epoch": { "$gt": start_epoch }},
                        {"netflow.stop_epoch": { "$lt": stop_epoch }},
                        ] },
                        { "$and": [
                        {"netflow.start_epoch": { "$lt": start_epoch }},
                        {"netflow.stop_epoch": { "$gt": stop_epoch }},
                        ]}
                        ]}
                        ]}}, 
                        { "$project": { "ID": "$_id", "document": "$$ROOT"}},{ "$sort": { "ID": 1 }}, { "$limit": self.sizeLimit }])

                results_found.append({ 'id': ID, 'sessions': flow_results, 'origin': orig_alert })

        return results_found
        
    '''Function to search flow records'''       
    def search_flow(self, request, orig_search=False):
        if not orig_search:
            event_search = {}
        
            if len(request['src_ip']) > 0:
                event_search['src_ip'] = str(request['src_ip'])
            
            if len(request['src_port']) > 0:
                try:
                    event_search['src_port'] = int(request['src_port'])
                except ValueError:
                    pass
            
            if len(request['dest_ip']) > 0:
                event_search['dest_ip'] = str(request['dest_ip'])
            
            if len(request['dest_port']) > 0:
                try:
                    event_search['dest_port'] = int(request['dest_port'])
                except ValueError:
                    pass
            
            if len(request['sensor']) > 0:
                event_search['sensor'] = str(request['sensor'])
            
            if len(request['proto']) > 0:
                try:
                    proto = int(request['proto'])

                    if proto == 1: 
                        event_search['proto'] = 'ICMP'

                    if proto == 4:
                        event_search['proto'] = 'IP'

                    if proto == 6:
                        event_search['proto'] = 'TCP'

                    if proto == 8:
                        event_search['proto'] = 'EGP'

                    if proto == 9:
                        event_search['proto'] = 'IGP'

                    if proto == 17:
                        event_search['proto'] = 'UDP'

                    if proto == 27:
                        event_search['proto'] = 'RDP'

                    if proto == 41:
                        event_search['proto'] = 'IPv6'

                    if proto == 51:
                        event_search['proto'] = 'AH'

                except:
                    try:
                        event_search['proto'] = str(request['proto'].upper())

                    except:
                        return 'Protocol not found', event_search

            if len(request['start']) > 0:
                 start_epoch = time.mktime(time.strptime(request['start'], '%m-%d-%Y %H:%M:%S'))

            else:
                 start_epoch = 0
                 
            if len(request['stop']) > 0:
                 stop_epoch = time.mktime(time.strptime(request['stop'], '%m-%d-%Y %H:%M:%S'))

            else:
                 stop_epoch = 0
             
            if start_epoch == 0 and stop_epoch == 0:
                 start_epoch = time.time() - 600
                 stop_epoch = time.time()

            elif start_epoch == 0 and stop_epoch > 0:
                 start_epoch = stop_epoch - 600

            elif start_epoch > 0 and stop_epoch == 0:
                 if (start_epoch + 600) > time.time():
                     stop_epoch = time.time()

                 else:
                     stop_epoch = start_epoch + 600

        else:
            event_search = request
            stop_epoch = event_search.pop('stop_epoch')
            start_epoch = event_search.pop('start_epoch')
                     
        results_found = self.flow.aggregate([
          { '$match': 
            { '$and': [ 
              event_search, 
              { '$or': [
                { '$and': [
                  { 'netflow.start_epoch': { '$gt': start_epoch }}, 
                  { 'netflow.start_epoch': { '$lt': stop_epoch }}
                ]}, 
                { '$and': [
                  { 'netflow.stop_epoch': { '$gt': start_epoch }}, 
                  { 'netflow.stop_epoch': { '$lt': stop_epoch }}
                ]}, 
                { '$and': [
                  { 'netflow.start_epoch': { '$lt': start_epoch }}, 
                  { 'netflow.stop_epoch': { '$gt': stop_epoch }}
                ]}
              ]}
            ]}
          }, 
          { '$project': { 'ID': '$_id', 'document': '$$ROOT' }}, 
          { '$sort': { 'ID': 1 }}, 
          { '$limit': self.sizeLimit }
        ])
        
        event_search['start_epoch'] = start_epoch
        event_search['stop_epoch'] = stop_epoch
        
        return results_found, event_search
