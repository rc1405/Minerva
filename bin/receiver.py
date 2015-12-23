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
import ssl
import platform
import json
import subprocess
from multiprocessing import Process, active_children, Queue
from socket import socket, AF_INET, SOCK_STREAM

import M2Crypto
import pymongo
from pytz import timezone
from dateutil.parser import parse

from Minerva import core
from Minerva.receiver import MongoInserter, AlertProcessor, PCAPprocessor, EventListener

class putEvent(object):
    def __init__(self, cur_config):
        self.cur_config = cur_config
        if cur_config['redis']['enabled']:
            import redis
            self.putter = self.redisEvents
            self.r = redis.Redis(host=cur_config['redis']['server'], port=cur_config['redis']['port'])
            self.key = cur_config['redis']['key']
        else:
            self.putter = self.queueEvents
        self.queue = Queue()

    def redisEvents(self, event):
        self.r.rpush(self.key, json.dumps(event))

    def queueEvents(self, event):
        self.queue.put(event)

            
def insert_data(minerva_core, log_queue):
    try:
        inserter = MongoInserter(minerva_core, log_queue)
        if minerva_core.conf['Event_Receiver']['redis']['enabled']:
            inserter.insert_redis()
        else:
            inserter.insert_data()
    except:
        return

def receiver(minerva_core, pname, event_method):
    try:
        ip, port = pname.split('-')
        listener = EventListener(minerva_core, int(minerva_core.conf['Event_Receiver']['listen_ip'][ip]['receive_threads']))
        proc = AlertProcessor(minerva_core, event_method)
        listener.listener(pname, proc.process)
    except:
        return

def pcap_receiver(minerva_core, pname):
    try:
        listener = EventListener(minerva_core, int(minerva_core.conf['Event_Receiver']['PCAP']['threads']))
        proc = PCAPprocessor(minerva_core)
        listener.listener(pname, proc.process)
    except:
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
    results = list(certdb.find({"type": "receiver", "ip": cur_config['PCAP']['ip'] }))
    if len(results) == 0:
        certdb.insert({"type": "receiver", "ip": cur_config['PCAP']['ip'], "cert": open(cur_config['certs']['server_cert'],'r').read() } )
    else:
        cert = results[0]['cert']
        if cert != open(cur_config['certs']['server_cert'],'r').read():
            print('Cert Changed')
            certdb.update({"type": "receiver", "ip": cur_config['PCAP']['ip'] },{ "$set": { "cert": open(cur_config['certs']['server_cert'],'r').read() }})
    return


def main():
    minerva_core = core.MinervaConfigs()
    config = minerva_core.conf
    cur_config = config['Event_Receiver']
    if not os.path.exists(cur_config['certs']['server_cert']) or not os.path.exists(cur_config['certs']['private_key']):
        genKey(cur_config, minerva_core)
    checkCert(cur_config, minerva_core)
    event_method = putEvent(cur_config)
    event_push = event_method.putter
    active_processes = []
    log_procs = []
    pcap_name = "%s-%s" % (cur_config['PCAP']['ip'], str(cur_config['PCAP']['port']))
    pcap_listener = Process(name=pcap_name, target=pcap_receiver, args=(minerva_core, pcap_name))
    pcap_listener.start()
    for lp in range(0,int(cur_config['insertion_threads'])):
        log_proc = Process(name='logger' + str(lp), target=insert_data, args=(minerva_core, event_method.queue))
        log_proc.start()
        log_procs.append(log_proc)
    try:
        for i in cur_config['listen_ip']:
            for p in cur_config['listen_ip'][i]['ports']:
                name = "%s-%s" % (i,p)
    	        pr = Process(name=name, target=receiver, args=((minerva_core, name, event_method)))
                pr.start()
                active_processes.append(pr)
        while True:
            for p in active_processes:
                if not p.is_alive():
                    active_processes.remove(p)
                    pr = Process(name=p.name, target=receiver, args=((minerva_core, p.name, event_method)))
                    pr.start()
                    active_processes.append(pr)
            for lp in log_procs:
                if not lp.is_alive():
                    lp.terminate()
                    log_procs.remove(lp)
                    log_proc = Process(name=lp.name, target=insert_data, args=(minerva_core, event_method.queue))
                    log_proc.start()
                    log_procs.append(log_proc)
            if not pcap_listener.is_alive():
                pcap_listener.join()
                pcap_listener = Process(name=pcap_name, target=pcap_receiver, args=(minerva_core, pcap_name))
                pcap_listener.start()
            #time.sleep(10)
            time.sleep(.001)
    except:
        for p in active_processes:
            p.terminate()
        for l in log_procs:
            l.terminate()
        pcap_listener.terminate()
        sys.exit()
main()
