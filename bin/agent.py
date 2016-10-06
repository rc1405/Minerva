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
import json
import subprocess
import pprint
import uuid

from multiprocessing import Process, Lock, active_children, Queue

import M2Crypto
import zmq

from Minerva import core
from Minerva.agent import TailLog, get_parser, AgentSubscriber, AgentPublisher, AgentWorker


def tailFile(cur_config, fname, channels):
    sensor_name = cur_config['sensor_name']
    ftype = cur_config['logfiles'][fname]['type']
    converter = get_parser(ftype, sensor_name)
    batchsize = int(cur_config['send_batch'])
    sendwait = int(cur_config['send_wait'])

    if ftype == 'suricata-redis-list':
        context = zmq.Context.instance()
        events = context.Socket(zmq.REQ)
        events.connect(channels['events'])
        channel = cur_config['logfiles'][fname]['channel']
        try:
            while True:
                if r.llen(channel) > 0:
                    total_length = r.llen(channel) - 1
                    events = r.lrange(0, total_length)
                    for event in events:
                        new_event = converter.convert(event)
                        if new_event:
                            events.send_json(new_event)
                            status = events.recv()
                        else:
                            continue
                    r.ltrim(channel, total_length, -1)
                else:
                    sleep(1)
        except:
            sys.exit()
    else:
        pfile = cur_config['logfiles'][fname]['position_file']
        ftailer = TailLog(channels, cur_config['send_batch'], converter, fname, pfile)
        ftailer.tail()

def worker(cur_config, channels):
    #context = zmq.Context.instance()
    #server = channels['context'].socket(zmq.PULL)
    #server = context.socket(zmq.PULL)
    #server.bind(channels['worker_main'])
    #update_lock = Lock()
    #action_fh, sig_fh = update_yara(minerva_core)
    #workers = EventWorker(minerva_core, channels, update_lock, action_fh.name, sig_fh.name)
    worker_procs = []
    #do_update = False
    #try:
    if 1 == 1:
        for wp in range(0,int(cur_config['worker_threads'])):
            #workers = EventWorker(minerva_core, channels, update_lock, action_fh.name, sig_fh.name)
            print('started %i' % wp)
            worker = AgentWorker(cur_config, channels)
            worker.start()
            worker_procs.append(worker)
        while True:
            for p in worker_procs:
                if not p.is_alive():
                    worker_procs.remove(p)
                    worker = AgentWorker(cur_config, channels)
                    worker.start()
                    p.join()
                    worker_procs.append(worker)

def publisher(cur_config, channels, start_workers):
    pub = AgentPublisher(cur_config, channels)
    pub.publish(start_workers)

def subscriber(cur_config, channels):
    sub = AgentSubscriber(cur_config, channels)
    sub.listen()

def genKey(cur_config):
    if not os.path.exists(os.path.dirname(cur_config['client_cert'])):
        os.makedirs(os.path.dirname(cur_config['client_cert']))
    if not os.path.exists(os.path.dirname(cur_config['client_private'])):
        os.makedirs(os.path.dirname(cur_config['client_private']))
    cmd = [ 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', cur_config['client_private'], '-out', cur_config['client_cert'], '-days', '3650', '-nodes', '-batch', '-subj', '/CN=%s' % cur_config['sensor_name'] ]
    subprocess.call(cmd)

def main():
    cur_config = core.MinervaConfigs().conf['Agent_forwarder']
    if not os.path.exists(cur_config['client_cert']) or not os.path.exists(cur_config['client_private']):
        genKey(cur_config)

    channels = {
        "pub": "ipc://%s" % str(uuid.uuid4()),
        "events": "ipc://%s" % str(uuid.uuid4()),
        "worker": "ipc://%s" % str(uuid.uuid4()),
    }

    log_procs = []
    work_procs = []

    sub_proc = Process(name='subscriber', target=subscriber, args=((cur_config,channels)))
    sub_proc.start()

    start_workers = Lock()

    pub_proc = Process(name='publisher', target=publisher, args=((cur_config, channels, start_workers)))
    pub_proc.start()

    worker_main = Process(name='worker_main', target=worker, args=(cur_config, channels))
    worker_main.start()

    time.sleep(5)

    if start_workers.acquire() :
    #try:
    #if 1 == 1:
        for l in cur_config['logfiles'].keys():
    	    pr = Process(name=l, target=tailFile, args=((cur_config, l, channels)))
            pr.start()
            log_procs.append(pr)

        #for wp in range(0,int(cur_config['worker_threads'])):
            #work_proc = Process(name='worker-%i' % wp, target=workers.start)
            #work_proc.start()
            #work_procs.append(work_proc)

        while True:
            for l in log_procs:
                if not l.is_alive():
                    pr = Process(name=l.name, target=tailFile, args=((cur_config, l.name, channels)))
                    pr.start()
                    log_procs.remove(l)
                    log_procs.append(pr)
            if not sub_proc.is_alive():
                sub_proc = Process(name='subscriber', target=subscriber, args=((cur_config, channels)))
                sub_proc.start()
            if not pub_proc.is_alive():
                pub_proc = Process(name='publisher', target=publisher, args=((cur_config, channels, start_workers)))
                pub_proc.start()
            if not worker_main.is_alive():
                worker_main.join()
                worker_main = Process(name='worker_main', target=worker, args=(cur_config, channels))
                worker_main.start()
            time.sleep(10)
    #except:
        #time.sleep(1)
        #for l in active_processes:
            #l.terminate()
        #listen_proc.terminate()
        #sender_proc.terminate()
        #sys.exit()
main()
