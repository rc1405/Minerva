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
import datetime

import pymongo

class alert_flow(object):

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
            orig_alert = self.alerts.find_one({ "_id": bson.objectid.ObjectId(ID) })
           
            try:
                decoded_packets = orig_alert['payload'].decode('base64')
            except:
                try:
                    decoded_packets = orig_alert['packet'].decode('base64')
                except:
                    decoded_packets = False
            if decoded_packets:
                hex_dump = []
                hex_packet = ""
                asc = ''
                for i in range(1, len(decoded_packets), 1):
                    if 1 == i % 32:
                        hex_dump.append( hex_packet +  "     " + asc + "\n")
                        hex_packet = "%04X: " % (i-1)
                        asc = ''
                    pos = ord(decoded_packets[i-1:i])
                    hex_packet = hex_packet + "%02X " % pos
                    if pos >= 32 and pos <=126:
                        asc = asc + str(decoded_packets[i-1:i])
                    else:
                        asc = asc + "."
                end_int = i
                if len(hex_packet) > 0:
                    if len(decoded_packets) > 31:
                        end_int += 1
                        while 1 != end_int % 32:
                            hex_packet = hex_packet + "   "
                            end_int += 1
                    hex_dump.append(hex_packet + "     " + asc + "\n")
                orig_alert['hex'] = hex_dump            
            else:
                orig_alert['hex'] = []

            flow_results = []

            src_ip = orig_alert['src_ip']
            try:
                src_port = orig_alert['src_port']
                dest_port = orig_alert['dest_port']
                dest_ip =orig_alert['dest_ip']
                proto = orig_alert['proto']
                timestamp = orig_alert['timestamp']
                start_time = timestamp - datetime.timedelta(seconds=300)
                stop_time = timestamp + datetime.timedelta(seconds=300)
                flow_results = self.flow.aggregate([ { "$match": 
                    { "$and": [
                    { "src_ip": src_ip, "src_port": src_port, "dest_ip": dest_ip, "dest_port": dest_port, "proto": proto },
                    { "$or": [
                    { "$and": [
                    { "netflow.start": { "$gt": start_time }},
                    { "netflow.start": { "$lt": stop_time }},
                    ] },
                    { "$and": [
                    {"netflow.end": { "$gt": start_time }},
                    {"netflow.end": { "$lt": stop_time }},
                    ] },
                    { "$and": [
                    {"netflow.start": { "$lt": start_time }},
                    {"netflow.end": { "$gt": stop_time }},
                    ]}
                    ]}
                    ]}}, 
                    { "$project": { "ID": "$_id", "document": "$$ROOT"}},{ "$sort": { "ID": 1 }}, { "$limit": self.sizeLimit }])

            except KeyError:
                dest_ip =orig_alert['dest_ip']
                proto = orig_alert['proto']
                timestamp = orig_alert['timestamp']
                start_time = timestamp - datetime.timedelta(seconds=300)
                stop_time = timestamp + datetime.timedelta(seconds=300)
                flow_results = self.flow.aggregate([ { "$match":
                    { "$and": [
                    { "src_ip": src_ip, "dest_ip": dest_ip, "proto": proto },
                    { "$or": [
                    { "$and": [
                    { "netflow.start": { "$gt": start_time }},
                    { "netflow.start": { "$lt": stop_time }},
                    ] },
                    { "$and": [
                    {"netflow.end": { "$gt": start_time }},
                    {"netflow.end": { "$lt": stop_time }},
                    ] },
                    { "$and": [
                    {"netflow.start": { "$lt": start_time }},
                    {"netflow.end": { "$gt": stop_time }},
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
                start_time = datetime.datetime.strptime(request['start'], '%m-%d-%Y %H:%M:%S')

            else:
                start_time = datetime.datetime.utcnow() - datetime.timedelta(seconds=600)

            if len(request['stop']) > 0:
                stop_time = datetime.datetime.strptime(request['stop'], '%m-%d-%Y %H:%M:%S')

            else:
                stop_time = datetime.datetime.utcnow() + datetime.timedelta(seconds=600)

        else:
            event_search = request
            stop_time = event_search.pop('stop_time')
            start_time = event_search.pop('start_time')
                     
        results = self.flow.find(
          { '$and': [
             event_search,
             { '$or': [
                { '$and': [
                  { 'netflow.start': { '$gt': start_time }},
                  { 'netflow.start': { '$lt': stop_time }}
                ]},
                { '$and': [
                  { 'netflow.end': { '$gt': start_time }},
                  { 'netflow.end': { '$lt': stop_time }}
                ]},
                { '$and': [
                  { 'netflow.start': { '$lt': start_time }},
                  { 'netflow.end': { '$gt': stop_time }}
                ]}
            ]}
          ]}).sort([("_id", pymongo.ASCENDING)]).limit(self.sizeLimit)
        
        numFound = results.count()
        results_found = map(self.map_flow, results)
        
        event_search['start_time'] = start_time
        event_search['stop_time'] = stop_time
        
        return numFound, results_found, event_search

    def map_flow(self, item):
        ret_dict = {}
        ret_dict['ID'] = item.pop('_id')
        ret_dict['document'] = item
        return ret_dict



