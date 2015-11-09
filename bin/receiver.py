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

def insert_data(config, log_queue):
    try:
        inserter = MongoInserter(config, log_queue)
        inserter.insert_data()
    except:
        return

def receiver(cur_config, pname, log_queue):
    try:
        ip, port = pname.split('-')
        listener = EventListener(cur_config, int(cur_config['Event_Receiver']['listen_ip'][ip]['receive_threads']))
        proc = AlertProcessor(cur_config, log_queue)
        listener.listener(pname, proc.process)
    except:
        return

def pcap_receiver(cur_config, pname):
    try:
        listener = EventListener(cur_config, int(cur_config['Event_Receiver']['PCAP']['threads']))
        proc = PCAPprocessor(cur_config)
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
    db = minerva_core.get_db()
    certdb = db.certs
    results = list(certdb.find({"type": "receiver", "ip": cur_config['PCAP']['ip'] }))
    if len(results) > 0:
        certdb.update({"type": "receiver", "ip": cur_config['PCAP']['ip'] },{ "$set": { "cert": open(cur_config['certs']['server_cert'],'r').read() }})
    else:
        certdb.insert({"type": "receiver", "ip": cur_config['PCAP']['ip'], "cert": open(cur_config['certs']['server_cert'],'r').read() } )



def main():
    minerva_core = core.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml'))
    config = minerva_core.conf
    cur_config = config['Event_Receiver']
    if not os.path.exists(cur_config['certs']['server_cert']) or not os.path.exists(cur_config['certs']['private_key']):
        genKey(cur_config, minerva_core)
    active_processes = []
    log_queue = Queue()
    log_procs = []
    pcap_name = "%s-%s" % (cur_config['PCAP']['ip'], str(cur_config['PCAP']['port']))
    pcap_listener = Process(name=pcap_name, target=pcap_receiver, args=(config, pcap_name))
    pcap_listener.start()
    for lp in range(0,int(cur_config['insertion_threads'])):
        log_proc = Process(name='logger' + str(lp), target=insert_data, args=(config, log_queue))
        log_proc.start()
        log_procs.append(log_proc)
    try:
        for i in cur_config['listen_ip']:
            for p in cur_config['listen_ip'][i]['ports']:
                name = "%s-%s" % (i,p)
    	        pr = Process(name=name, target=receiver, args=((config, name, log_queue)))
                pr.start()
                active_processes.append(pr)
        while True:
            for p in active_processes:
                if not p in active_children():
                    active_processes.remove(p)
                    pr = Process(name=p.name, target=receiver, args=((config, p.name, log_queue)))
                    pr.start()
                    active_processes.append(pr)
            for lp in log_procs:
                if not lp in active_children():
                    log_procs.remove(lp)
                    log_proc = Process(name=lp.name, target=insert_data, args=(config, log_queue))
                    log_proc.start()
                    log_procs.append(log_proc)
            if not pcap_listener in active_children():
                pcap_listener.join()
                pcap_listener = Process(name=pcap_name, target=pcap_receiver, args=(config, pcap_name))
                pcap_listener.start()
            time.sleep(10)
    except:
        for p in active_processes:
            p.terminate()
        for l in log_procs:
            l.terminate()
        pcap_listener.terminate()
        sys.exit()
main()
