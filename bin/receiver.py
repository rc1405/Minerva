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

    def ip_to_str(item):
        return str(item)

    def get_ips(item):
        try:
            ipaddress = netaddr.IPNetwork(item['address'])
        except:
            return
        if ipaddress.size > 1:
            priority = int(item['priority'])
            for i in map(self.ip_to_str, list(ipaddress.iter_hosts())):
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
        action_string = "rule %s\n{\n\tstrings:\n"
        rule_count = 1
        for s in watches[k]:
            sig_string = "rule %s\n{\n\tstrings:\n\t\t$1 = %s\n\tcondition:\n\t\tall of them\n}\n" % (s.replace('.','_'), s)
            sig_fh.writelines(sig_string)
            action_string = action_string + "\t\t$%i = %s\n"
            rule_count += 1
        if rule_count > 1:
            action_string = action_string + "\tcondition:\n\t\tany of them\n}\n"
            action_fs.writelines(action_string)

    sig_fh.flush()
    sig_fh.truncate()
    action_fh.flush()
    action_fh.truncate()

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
