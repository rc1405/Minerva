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


def tailFile(cur_config, minerva_core, fname, channels):
    sensor_name = cur_config['sensor_name']
    ftype = cur_config['logfiles'][fname]['type']
    converter = get_parser(ftype, sensor_name)
    batchsize = int(cur_config['send_batch'])
    sendwait = int(cur_config['send_wait'])

    log_client = minerva_core.get_socket(channels)
    log_client.send_multipart(['DEBUG', 'Reading log file %s with type %s' % (fname, ftype)])

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
                    self.logger.send_multipart(['DEBUG', "Agent log tailer received event for %s" % fname])
                    for event in events:
                        new_event = converter.convert(event)
                        if new_event:
                            events.send_json(new_event)
                            self.logger.send_multipart(['DEBUG', "Agent log tailer %s sending event to publisher" % fname])
                            status = events.recv()
                        else:
                            self.logger.send_multipart(['ERROR', "Agent log tailer unable to parse event for %s" % fname])
                            continue
                    r.ltrim(channel, total_length, -1)
                else:
                    sleep(1)
        except:
            sys.exit()
    else:
        try:
            pfile = cur_config['logfiles'][fname]['position_file']
            ftailer = TailLog(channels, cur_config['send_batch'], minerva_core, converter, fname, pfile)
            ftailer.tail()
        except:
            log_client.send_multipart(['DEBUG', 'Reading log file %s shutting down' % fname])
            log_client.close(linger=1)
            sys.exit()

def worker(cur_config, minerva_core, channels):
    log_client = minerva_core.get_socket(channels)
    worker_procs = []
    try:
        for wp in range(0,int(cur_config['worker_threads'])):
            worker = AgentWorker(cur_config, minerva_core, channels)
            worker.start()
            worker_procs.append(worker)
            log_client.send_multipart(['DEBUG', 'Starting worker #%i' % wp])
        while True:
            for p in worker_procs:
                if not p.is_alive():
                    worker_procs.remove(p)
                    worker = AgentWorker(cur_config, minerva_core, channels)
                    worker.start()
                    p.join()
                    worker_procs.append(worker)
                    log_client.send_multipart(['ERROR', 'Worker crashed, restarting'])
    except:
        log_client.send_multipart(['DEBUG', 'Worker Management Thread Shutting Down'])
        for i in worker_procs:
            i.terminate()
        sys.exit()

def publisher(cur_config, minerva_core, channels, start_workers):
    pub = AgentPublisher(cur_config, minerva_core, channels)
    pub.publish(start_workers)

def subscriber(cur_config, minerva_core, channels):
    sub = AgentSubscriber(cur_config, minerva_core, channels)
    sub.listen()

def genKey(cur_config):
    if not os.path.exists(os.path.dirname(cur_config['client_cert'])):
        os.makedirs(os.path.dirname(cur_config['client_cert']))
    if not os.path.exists(os.path.dirname(cur_config['client_private'])):
        os.makedirs(os.path.dirname(cur_config['client_private']))
    cmd = [ 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', cur_config['client_private'], '-out', cur_config['client_cert'], '-days', '3650', '-nodes', '-batch', '-subj', '/CN=%s' % cur_config['sensor_name'] ]
    subprocess.call(cmd)

if __name__ == '__main__':
    minerva_core = core.MinervaConfigs()
    cur_config = core.MinervaConfigs().conf['Agent_forwarder']

    if not os.path.exists(cur_config['client_cert']) or not os.path.exists(cur_config['client_private']):
        genKey(cur_config)

    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))

    channels = {
        "worker": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "pub": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "events": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "logger": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
    }

    log_procs = []
    work_procs = []

    log_proc = core.MinervaLog(minerva_core.conf, channels, 'agent')
    log_proc.start()

    log_client = minerva_core.get_socket(channels)

    sub_proc = Process(name='subscriber', target=subscriber, args=((cur_config, minerva_core, channels)))
    sub_proc.start()
    log_client.send_multipart(['DEBUG', 'Starting Subscriber Process'])

    start_workers = Lock()

    pub_proc = Process(name='publisher', target=publisher, args=((cur_config, minerva_core, channels, start_workers)))
    pub_proc.start()
    log_client.send_multipart(['DEBUG', 'Starting Publisher Process'])

    worker_main = Process(name='worker_main', target=worker, args=(cur_config, minerva_core, channels))
    worker_main.start()
    log_client.send_multipart(['DEBUG', 'Starting Worker Manager Thread'])

    try:
        for l in cur_config['logfiles'].keys():
            pr = Process(name=l, target=tailFile, args=((cur_config, minerva_core, l, channels)))
            pr.start()
            log_procs.append(pr)
            log_client.send_multipart(['DEBUG', 'Starting processing file %s' % l])
        log_client.send_multipart(['INFO', 'Agent processes started'])
        while True:
            for l in log_procs:
                if not l.is_alive():
                    pr = Process(name=l.name, target=tailFile, args=((cur_config, minerva_core, l.name, channels)))
                    pr.start()
                    log_procs.remove(l)
                    log_procs.append(pr)
                    log_client.send_multipart(['ERROR', 'Processing file %s failed, restarting' % l.name])
            if not sub_proc.is_alive():
                sub_proc = Process(name='subscriber', target=subscriber, args=((cur_config, minerva_core, channels)))
                sub_proc.start()
                log_client.send_multipart(['ERROR', 'Subscriber Process crashed, restarting'])
            if not pub_proc.is_alive():
                pub_proc = Process(name='publisher', target=publisher, args=((cur_config, minerva_core, channels, start_workers)))
                pub_proc.start()
                log_client.send_multipart(['ERROR', 'Publisher Process crashed, restarting'])
            if not worker_main.is_alive():
                worker_main.join()
                worker_main = Process(name='worker_main', target=worker, args=(cur_config, minerva_core, channels))
                worker_main.start()
                log_client.send_multipart(['ERROR', 'Worker Manager Thread crashed, restarting'])
            if not log_proc.is_alive():
                log_proc = core.MinervaLog(minerva_core.conf, channels, 'agent')
                log_proc.start()
                log_client.send_multipart(['ERROR', 'Logging Thread crashed, restarting'])
            time.sleep(10)
    except:
        log_client.send_multipart(['INFO', 'Agent processes shutting down'])
        for l in log_procs:
            l.terminate()
            log_client.send_multipart(['DEBUG', 'Terminating Process %s' % l.name])
        sub_proc.terminate()
        log_client.send_multipart(['DEBUG', 'Terminating Subscriber Process'])
        pub_proc.terminate()
        log_client.send_multipart(['DEBUG', 'Terminating Publishing Process'])
        worker_main.terminate()
        log_client.send_multipart(['DEBUG', 'Terminating Worker Thread Manager'])
        for i in channels.keys():
            if os.path.exists(channels[i][6:]):
                os.remove(channels[i][6:])
        log_client.send_multipart(['DEBUG', 'Terminating Logging Thread'])
        log_client.send_multipart(['KILL', 'Stop Logger thread'])
        sys.exit()
