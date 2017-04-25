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
import datetime

import pymongo

class dns(object):

    '''Initialize Class'''
    def __init__(self, minerva_core):
        db = minerva_core.get_db()
        self.alerts = db.alerts
        self.dns = db.dns
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']

    '''Function to get the flow records for a given alert'''
    def get_dns(self, IDs):
        results_found = []

        for ID in IDs:
            orig_alert = self.alerts.find_one({ "_id": bson.objectid.ObjectId(ID) })
            flow_results = []

            src_ip = orig_alert['src_ip']
            src_port = orig_alert['src_port']
            dest_ip =orig_alert['dest_ip']
            dest_port = orig_alert['dest_port']
            proto = orig_alert['proto']
            timestamp = orig_alert['timestamp']
            start_time = timestamp - datetime.timedelta(seconds=300)
            stop_time = timestamp + datetime.timedelta(seconds=300)
            dns_results = self.dns.find( {  
                    "$and": [
                    { "src_ip": src_ip, "src_port": src_port, "dest_ip": dest_ip, "dest_port": dest_port, "proto": proto },
                    { "$and": [
                    { "timestamp": { "$gt": start_time }},
                    { "timestamp": { "$lt": stop_time }},
                    ] },
                    ]}).sort([("_id", pymongo.ASCENDING)]).limit(self.sizeLimit)
            numFound = dns_results.count()
            dns_results = map(self.map_dns, dns_results)
            results_found.append({ 'id': ID, 'sessions': dns_results, 'origin': orig_alert, 'numFound': numFound })
 
        return results_found
        
    def map_dns(self, item):
        ret_dict = {}
        ret_dict['ID'] = item.pop('_id')
        ret_dict['document'] = item
        return ret_dict
        
    '''Function to search flow records'''       
    def search_dns(self, request, orig_search=False):
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
            
            event_search['proto'] = str(request['proto'])
          
            if len(request['query_type']) > 0:
                event_search['dns.type'] = str(request['query_type'])
          
            if len(request['rrtype']) > 0:
                event_search['dns.rrtype'] = str(request['rrtype'])

            if len(request['rcode']) > 0:
                event_search['dns.rcode'] = str(request['rcode'])
 
            if len(request['rrname']) > 0:
                event_search['dns.rrname'] = str(request['rrname'])
          
            if len(request['rdata']) > 0:
                event_search['dns.rdata'] = str(request['rdata'])

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

        results = self.dns.find(
          { "$and": [
             event_search,
                { "$and": [
                  { "timestamp": { "$gt": start_time }},
                  { "timestamp": { "$lt": stop_time }}
                ]},
          ]}).sort([("_id", pymongo.ASCENDING)]).limit(self.sizeLimit)

        numFound = results.count()
        results_found = map(self.map_dns, results)
        
        event_search['start_time'] = start_time
        event_search['stop_time'] = stop_time
        
        return numFound, results_found, event_search

    def map_dns(self, item):
        ret_dict = {}
        ret_dict['ID'] = item.pop('_id')
        ret_dict['document'] = item
        return ret_dict
