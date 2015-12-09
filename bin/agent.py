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
import pprint
from multiprocessing import Process, Lock, active_children, Queue
from socket import socket, AF_INET, SOCK_STREAM

import M2Crypto

from Minerva import core
from Minerva.agent import TailLog, get_parser, PCAPprocessor, RequestListener, carvePcap, EventSender

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
        
def tailFile(cur_config, fname, event_push):
    sensor_name = cur_config['sensor_name']
    ftype = cur_config['logfiles'][fname]['type']
    converter = get_parser(ftype, sensor_name)
    batchsize = int(cur_config['target_addr']['send_batch'])
    sendwait = int(cur_config['target_addr']['send_wait'])
    if ftype in ['suricata-redis-channel','suricata-redis-list']:
        if cur_config['logfiles'][fname]['use_main']:
            r = redis.Redis(host=cur_config['redis']['server'], port=cur_config['redis']['port'])
        else:
            r = redis.Redis(host=cur_config['logfiles'][fname]['server'], port=cur_config['logfiles'][fname]['port'])
    if ftype == 'suricata-redis-channel':
        pubsub = r.pubsub()
        pubsub.subscribe(cur_config['logfiles'][fname]['channel'])
        try:
            for item in pubsub.listen():
                new_event = converter.convert(item['data'])
                if new_event:
                    #r.rpush(key, json.dumps(new_event))
                    event_push(new_event)
                else:
                    continue
        except:
            sys.exit()
    elif ftype == 'suricata-redis-list':
        channel = cur_config['logfiles'][fname]['channel']
        try:
            while True:
                if r.llen(channel) > 0:
                    total_length = r.llen(channel) - 1
                    events = r.lrange(0, total_length)
                    for event in events:
                        new_event = converter.convert(event)
                        if new_event:
                            #r.rpush(key, json.dumps(new_event))
                            event_push(new_event)
                        else:
                            continue
                    r.ltrim(channel, total_length, -1)
                else:
                    sleep(1)
        except:
            sys.exit()
    else:
        pfile = cur_config['logfiles'][fname]['position_file']
        ftailer = TailLog(fname, pfile)
        try:
            for event in ftailer.tail():
                new_event = converter.convert(event)
                if new_event:
                    #r.rpush(key, json.dumps(new_event))
                    event_push(new_event)
                else:
                    continue
        except:
            ftailer.write_pos()
            sys.exit()

def requestSender(cur_config, event_method):
    event_sender = EventSender(cur_config, event_method)
    event_sender.sender()

def requestListener(cur_config):
    listener = RequestListener(cur_config)
    carver = carvePcap(cur_config)
    proc = PCAPprocessor(cur_config, carver)
    listener.listener(proc.process)

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
    event_method = putEvent(cur_config)
    event_push = event_method.putter
    active_processes = []
    send_lock = Lock()
    listen_proc = Process(name='listen-proc', target=requestListener, args=((cur_config,)))
    listen_proc.start()
    sender_proc = Process(name='sender-proc', target=requestSender, args=((cur_config,event_method)))
    sender_proc.start()
    try:
        for l in cur_config['logfiles'].keys():
    	    pr = Process(name=l, target=tailFile, args=((cur_config, l, event_push)))
            pr.start()
            active_processes.append(pr)
        while True:
            for l in active_processes:
                if not l.is_alive():
                    active_processes.remove(l)
                    pr = Process(name=l.name, target=tailFile, args=((cur_config, l.name, event_push)))
                    pr.start()
                    active_processes.append(pr)
            if not listen_proc.is_alive():
                listen_proc = Process(name='listen-proc', target=requestListener, args=((cur_config,)))
                listen_proc.start()
            if not sender_proc.is_alive():
                sender_proc = Process(name='sender-proc', target=requestSender, args=((cur_config, event_method)))
                sender_proc.start()
            time.sleep(10)
    except:
        time.sleep(1)
        for l in active_processes:
            l.terminate()
        listen_proc.terminate()
        sender_proc.terminate()
        sys.exit()
main()
