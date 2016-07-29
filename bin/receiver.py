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


import os
import time
import sys
import platform
import subprocess
import uuid

from multiprocessing import Process, active_children, Lock
import threading
from tempfile import NamedTemporaryFile

import pymongo
import zmq
import netaddr

from Minerva import core
from Minerva.receiver import EventReceiver, EventPublisher, EventWorker
            
def receiver(pname, channels, worker_lock):
    #try:
        listener = EventReceiver(worker_lock, channels)
        listener.listen(pname)
    #except:
        #return

def publisher(minerva_core, channels, cur_config):
    pub = EventPublisher(minerva_core, channels, cur_config)
    pub.publish()


def work_thread(minerva_core, channels, update_lock, action_file, sig_file):
    workers = EventWorker(minerva_core, channels, update_lock, action_file, sig_file)
    workers.start()


def worker(minerva_core, cur_config, channels):
    context = zmq.Context.instance()
    #server = channels['context'].socket(zmq.PULL)
    server = context.socket(zmq.PULL)
    server.bind(channels['worker_main'])
    update_lock = Lock()
    action_fh, sig_fh = update_yara(minerva_core)
    #workers = EventWorker(minerva_core, channels, update_lock, action_fh.name, sig_fh.name)
    worker_procs = []
    do_update = False
    #try:
    if 1 == 1:
        for wp in range(0,int(cur_config['worker_threads'])):
            #workers = EventWorker(minerva_core, channels, update_lock, action_fh.name, sig_fh.name)
            print('started %i' % wp)
            worker = EventWorker(minerva_core, channels, update_lock, action_fh.name, sig_fh.name)
            worker.start()
            worker_procs.append(worker)
        while True:
            for p in worker_procs:
                if not p.is_alive():
                    worker_procs.remove(p)
                    worker = EventWorker(minerva_core, channels, update_lock, action_fh.name, sig_fh.name)
                    worker.start()
                    p.join()
                    worker_procs.append(worker)
            if not do_update:
                if server.poll(1000):
                    yara_update.recv()
                    do_update = True
            else: 
                update_lock.acquire()
                update_yara(minerva_core, action=action_fh, sig=sig_fh)
                update_lock.release()
                do_update = False
            time.sleep(1)
    #except:
        #for w in worker_procs:
            #w.terminate()
        #action_fh.close()
        #sig_fh.close()
        #server.close()
        #return

def update_yara(minerva_core, action=None, sig=None):
    if not action:
        action_fh = NamedTemporaryFile()
        return_stuff = True
    else:
        action_fh.seek(0)
        return_stuff = False
    if not sig:
        sig_fh = NamedTemporaryFile()
    else:
        sig_fh.seek(0)

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
            return

        if ipaddress.size > 1:
            priority = int(item['priority'])
            for i in map(ip_to_str, list(ipaddress.iter_hosts())):
                watches['IP_%i' % priority].append(i)
            return 'something'
        else:
            watches['IP_%i' % int(item['priority'])].append(item['address'])
            return 'something'

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
            sig_fh.writelines(sig_string)
            rule_count += 1

    sig_fh.flush()
    sig_fh.truncate()


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
        action_fh.writelines("rule %s\n{\n\tstrings:\n" % k)
        rule_count = 1
        for s in filters[k]:
            cur_conditions = []
            for r in s:
                action_fh.writelines("\t\t$%i = %s\n" % (rule_count, r))
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
        action_fh.writelines(condition)

    action_fh.flush()
    action_fh.truncate()
    time.sleep(1)
    if return_stuff:
        return action_fh, sig_fh
    else:
        return

def genKey(cur_config, minerva_core):
    if not os.path.exists(os.path.dirname(cur_config['certs']['server_cert'])):
        os.makedirs(os.path.dirname(cur_config['certs']['server_cert']))
    if not os.path.exists(os.path.dirname(cur_config['certs']['private_key'])):
        os.makedirs(os.path.dirname(cur_config['certs']['private_key']))
    cmd = [ 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', cur_config['certs']['private_key'], '-out', cur_config['certs']['server_cert'], '-days', '3650', '-nodes', '-batch', '-subj', '/CN=%s' % platform.node() ]
    subprocess.call(cmd)

def checkCert(cur_config, minerva_core):
    db = minerva_core.get_db()
    certdb = db.certs
    results = list(certdb.find({"type": "receiver" }))
    if len(results) == 0:
        if not os.path.exists(cur_config['certs']['server_cert']) or not os.path.exists(cur_config['certs']['private_key']):
            genKey(cur_config, minerva_core)
        certdb.insert({
            "type": "receiver", 
            "cert": open(cur_config['certs']['server_cert'],'r').read(), 
            "key": open(cur_config['certs']['private_key']).read() 
        } )
        for i in cur_config['listen_ip']:
            for p in cur_config['listen_ip'][i]['rec_ports']:
                certdb.update({"type": "receiver"}, { "$push": { "receivers": "%s-%i" % (i, p) }})

    else:
        if 'receivers' in results[0].keys():
            receivers = results[0]['receivers']
        for i in cur_config['listen_ip']:
            for p in cur_config['listen_ip'][i]['rec_ports']:
                if not "%s-%i" % (i, p) in receivers:
                    certdb.update({"type": "receiver"}, { "$push": { "receivers": "%s-%i" % (i, p) }})
    return


def main():
    minerva_core = core.MinervaConfigs()
    config = minerva_core.conf
    cur_config = config['Event_Receiver']
 
    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))

    channels = {
        "worker": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "worker_main": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "pub": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "receiver": {},
    }

    for i in cur_config['listen_ip']:
        for p in cur_config['listen_ip'][i]['rec_ports']:
            name = "%s-%s" % (i,p)
            channels['receiver']["%s-%s" % (i,p)] = "ipc://%s/%s" % (base_dir, str(uuid.uuid4()))

    checkCert(cur_config, minerva_core)

    active_processes = []

    pub_listener = Process(name='publisher', target=publisher, args=(minerva_core, channels, cur_config))
    pub_listener.start()

    worker_main = Process(name='worker_main', target=worker, args=(minerva_core, cur_config, channels))
    worker_main.start()

    worker_lock = Lock()

    #try:
    if 1 == 1:
        for i in cur_config['listen_ip']:
            for p in cur_config['listen_ip'][i]['rec_ports']:
                name = "%s-%s" % (i,p)
    	        pr = Process(name=name, target=receiver, args=((name, channels, worker_lock)))
                pr.start()
                active_processes.append(pr)
        while True:
            for p in active_processes:
                if not p.is_alive():
                    active_processes.remove(p)
                    pr = Process(name=p.name, target=receiver, args=((p.name, channels, worker_lock)))
                    pr.start()
                    p.join()
                    active_processes.append(pr)
            if not pub_listener.is_alive():
                pub_listener.join()
                pub_listener = Process(name='publisher', target=publisher, args=(minerva_core, channels, cur_config))
                pub_listener.start()
            if not worker_main.is_alive():
                worker_main.join()
                worker_main = Process(name='worker_main', target=worker, args=(minerva_core, cur_config, channels))
                worker_main.start()
            time.sleep(1)
    #except:
        #for p in active_processes:
            #p.terminate()
        #pub_listener.terminate()
        #worker_main.terminate()
        #sys.exit()
main()
