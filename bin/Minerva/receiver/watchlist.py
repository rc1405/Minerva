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

from tempfile import NamedTemporaryFile

import netaddr

class Watchlist():
    def update_yara(self, minerva_core, log_client, action=None, sig=None):
        if action is None:
            action = NamedTemporaryFile()
            return_stuff = True
        else:
            action.seek(0)
            return_stuff = False
        if sig is None:
            sig = NamedTemporaryFile()
        else:
            sig.seek(0)
    
        db = minerva_core.get_db()
    
        def get_domains(item):
            watches['domain_%i' % int(item['priority'])].append(item['domain'])
            return 'something'
    
        def ip_to_str(item):
            return str(item)
    
        def get_ips(item):
            try:
                ipaddress = netaddr.IPNetwork(item['address'])
            #except:
                #return
            except Exception as e:
                print('{}: {}'.format(e.__class__.__name__,e))
    
            if ipaddress.size > 1:
                priority = int(item['priority'])
                for i in map(ip_to_str, list(ipaddress.iter_hosts())):
                    watches['IP_%i' % priority].append(i)
            else:
                watches['IP_%i' % int(item['priority'])].append(item['address'])
    
        watchlist = db.watchlist
    
        watches = {
            'IP_5': [],
            'IP_4': [],
            'IP_3': [],
            'IP_2': [],
            'IP_1': [],
            'domain_5': [],
            'domain_4': [],
            'domain_3': [],
            'domain_2': [],
            'domain_1': [],
        }
    
        map(get_ips, list(db.watchlist.aggregate([{ "$match": { "type": "ip_address", "STATUS": "ENABLED" }},{ "$project": { "address": "$criteria", "priority": "$priority" }}])))
        map(get_domains, list(db.watchlist.aggregate([{ "$match": { "type": "domain", "STATUS": "ENABLED" }}, { "$project": { "domain": "$criteria", "priority": "$priority" }}])))
    
        for k in watches.keys():
            rule_count = 1
            for s in watches[k]:
                sig_string = "rule %s__%s\n{\n\tstrings:\n\t\t$1 = \"%s\\\"\"\n\tcondition:\n\t\tall of them\n}\n" % (k, s.replace('.','_'), s)
                sig.writelines(sig_string)
                rule_count += 1
    
        log_client.send_multipart(['DEBUG','Found %i Watchlist Items' % (rule_count - 1)])
    
        sig.flush()
        sig.truncate()
    
    
        filters = {
            'P__inc__1': [],
            'P__dec__1': [],
            'P__inc__2': [],
            'P__dec__2': [],
            'P__inc__3': [],
            'P__dec__3': [],
            'P__inc__4': [],
            'P__dec__4': [],
            'P__inc__5': [],
            'P__dec__5': [],
            'S__C': [],
            'S__E': [],
            'S__O': [],
        }
    
        def get_rule_type(item):
            action_pre = item['action_type'][:1].upper()
            if action_pre == 'P':
                if int(item['action_value']) > 0:
                    action_method = 'inc'
                    action_value = int(item['action_value'])
                else:
                    action_method = 'dec'
                    action_value = abs(item['action_value'])
    
                rule_type = '%s__%s__%i' % (action_pre, action_method, action_value)
            else:
                action_method = item['action_value'][:1].upper()
                rule_type = '%s__%s' % (action_pre, action_method)
            return rule_type
    
        def get_sids(item):
    
            rule_type = get_rule_type(item)
    
            filters[rule_type].append([
                "sid\":(*?\w+)\"%s\"" %  str(item['sig_id']),
                "rev\":(*?\w+)\"%s\"" % str(item['rev']),
                "gid\":(*?\w+)\"%s\"" % str(item['gid'])
            ])
    
        def get_cat(item):
            rule_type = get_rule_type(item)
    
            filters[rule_type].append([
                "category\":(*?\w+)\"%s\"" % item['category']
            ])
    
        def get_addresses(item):
            rule_type = get_rule_type(item)
            filters[rule_type].append([
                "\"%s\"" % item['ip_address']
            ])
    
        def get_sessions(item):
            rule_type = get_rule_type(item)
           
            filters[rule_type].append([
                "\"%s\"" % item['src_ip'],
                "\"%s\"" % item['dest_ip']
            ])
    
        def get_sigAddress(item):
            rule_type = get_rule_type(item)
            filters[rule_type].append([
                "sid\":(*?\w+)\"%s\"" %  str(item['sig_id']),
                "rev\":(*?\w+)\"%s\"" % str(item['rev']),
                "gid\":(*?\w+)\"%s\"" % str(item['gid']),
                "\"%s\"" % item['ip_address']
            ])
    
        def get_sigSession(item):
            rule_type = get_rule_type(item)
            filters[rule_type].append([
                "sid\":(*?\w+)\"%s\"" %  str(item['sig_id']),
                "rev\":(*?\w+)\"%s\"" % str(item['rev']),
                "gid\":(*?\w+)\"%s\"" % str(item['gid']),
                "\"%s\"" % item['src_ip'],
                "\"%s\"" % item['dest_ip']
            ])
    
        watch_filters = db.filters
    
        map(get_sids, list(watch_filters.aggregate([{ "$match": { "type": "signature" }},
            { "$project": { 
                  "sig_id": "$sig_id", 
                  "rev": "$rev", 
                  "gid": "$gid", 
                  "action_type": "$action_type", 
                  "action_value": "$action_value" 
            }}])))
    
        map(get_cat, list(watch_filters.aggregate([{ "$match": { "type": "categories" }}, 
            { "$project": { 
                  "category": "$category", 
                  "action_type": "$action_type", 
                  "action_value": "$action_value"  
            }}])))

        map(get_addresses, list(watch_filters.aggregate([{ "$match": { "type": "address" }}, 
            { "$project": { 
                  "ip_address": "$ip_address", 
                  "action_type": "$action_type", 
                  "action_value": "$action_value"
            }}])))
    
        map(get_sessions, list(watch_filters.aggregate([{ "$match": { "type": "session" }}, 
            { "$project": { 
                  "src_ip": "$src_ip", 
                  "dest_ip": "$dest_ip", 
                  "action_type": "$action_type", 
                  "action_value": "$action_value" 
            }}])))
    
        map(get_sigAddress, list(watch_filters.aggregate([{ "$match": { "type": "sig_address"}}, 
            { "$project": { 
                  "sig_id": "$sig_id", 
                  "rev": "$rev", 
                  "gid": "$gid", 
                  "ip_address": "$ip_address", 
                  "action_type": "$action_type", 
                  "action_value": "$action_value" 
            }}])))
    
        map(get_sigSession, list(watch_filters.aggregate([{ "$match": { "type": "sig_session"}}, 
            { "$project": { 
                  "sig_id": "$sig_id", 
                  "rev": "$rev", 
                  "gid": "$gid", 
                  "src_ip": "$src_ip", 
                  "dest_ip": "$dest_ip", 
                  "action_type": "$action_type", 
                  "action_value": "$action_value" 
            }}])))
    
        for k in filters.keys():
            if len(filters[k]) == 0:
                continue
            conditions = []
            action.writelines("rule %s\n{\n\tstrings:\n" % k)
            rule_count = 1
            for s in filters[k]:
                cur_conditions = []
                for r in s:
                    action.writelines("\t\t$%i = %s\n" % (rule_count, r))
                    cur_conditions.append(rule_count)
                    rule_count += 1
                conditions.append(cur_conditions)
    
            condition = '\tcondition:\n'
            ccount = 1
            for c in conditions:
                icount = 1
                if len(c) > 1:
                    if ccount == 1:
                        condition = condition + "\t\tall of ( "
                    else:
                        condition = condition + "\t\tor all of ( "
                        
                    for x in c:
                        if icount == len(c):
                            condition = condition + "$%i" % x
                        else:
                            condition = condition + "$%i," % x
                        icount += 1
                    condition = condition + ")\n"
                else:
                    if ccount == 1:
                        condition = condition + "\t\t$%i" % c[0]
                    else:
                        condition = condition + "\t\tor $%i" % c[0]
                ccount += 1
            condition = condition + "\n}\n"
            action.writelines(condition)
    
        log_client.send_multipart(['DEBUG','Found %i Rule Filters' % (rule_count - 1)])
        action.flush()
        action.truncate()
        time.sleep(1)
        if return_stuff:
            return action, sig
        else:
            return
