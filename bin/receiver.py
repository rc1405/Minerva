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
from tempfile import NamedTemporaryFile

import zmq

from Minerva import core
from Minerva.receiver import EventReceiver, EventPublisher, EventWorker, Watchlist
            
def worker(minerva_core, cur_config, channels):
    context = zmq.Context.instance()
    log_client = minerva_core.get_socket(channels)
    server = context.socket(zmq.PULL)
    server.bind(channels['worker_main'])
    update_lock = Lock()
    watchlist = Watchlist()
    action_fh, sig_fh = watchlist.update_yara(minerva_core, log_client)
    worker_procs = []
    do_update = False
    try:
        for wp in range(0,int(cur_config['worker_threads'])):
            log_client.send_multipart(['DEBUG', 'Started Worker #%i' % wp])
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
                    log_client.send_multipart(['ERROR', 'Worker thread crashed, restarting'])
            if not do_update:
                if server.poll(1000):
                    server.recv()
                    do_update = True
            else: 
                log_client.send_multipart(['DEBUG', 'Watchlist and Event Filter update started'])
                update_lock.acquire()
                watchlist.update_yara(minerva_core, log_client, action=action_fh, sig=sig_fh)
                update_lock.release()
                do_update = False
                log_client.send_multipart(['DEBUG', 'Watchlist and Event Filter update finished'])
            time.sleep(1)
    except Exception as e:
        print('{}: {}'.format(e.__class__.__name__,e))
        log_client.send_multipart(['INFO', 'Receiver Workers Shutting down'])
        for w in worker_procs:
            w.terminate()
        action_fh.close()
        sig_fh.close()
        server.close()
        sys.exit()

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
            "SERVER": "receiver", 
            "type": "receiver", 
            "cert": open(cur_config['certs']['server_cert'],'r').read(), 
            "key": open(cur_config['certs']['private_key']).read() 
        } )
    for i in cur_config['listen_ip']:
        for p in cur_config['listen_ip'][i]['rec_ports']:
            certdb.update({"SERVER": "receiver"}, { "$addToSet": { "receivers": "%s-%i-%i" % (i, p, cur_config['listen_ip'][i]['pub_port']) }})

    return


if __name__ == '__main__':
    minerva_core = core.MinervaConfigs()
    config = minerva_core.conf
    cur_config = config['Event_Receiver']
 
    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))

    channels = {
        "worker": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "worker_main": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "pub": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "logger": "ipc://%s/%s" % (base_dir, str(uuid.uuid4())),
        "receiver": {},
    }


    for i in cur_config['listen_ip']:
        for p in cur_config['listen_ip'][i]['rec_ports']:
            name = "%s-%s" % (i,p)
            channels['receiver']["%s-%s" % (i,p)] = "ipc://%s/%s" % (base_dir, str(uuid.uuid4()))

    checkCert(cur_config, minerva_core)

    active_processes = []

    log_proc = core.MinervaLog(config, channels, 'receiver')
    log_proc.start()

    log_client = minerva_core.get_socket(channels)

    pub_listener = EventPublisher(minerva_core, channels, cur_config)
    pub_listener.start()
    log_client.send_multipart(['DEBUG', 'Starting Receiver Publishing Process'])

    time.sleep(2)

    worker_main = Process(name='worker_main', target=worker, args=(minerva_core, cur_config, channels))
    worker_main.start()
    log_client.send_multipart(['DEBUG', 'Starting Worker Thread Manager'])

    worker_lock = Lock()

    try:
        for i in cur_config['listen_ip']:
            for p in cur_config['listen_ip'][i]['rec_ports']:
                name = "%s-%s" % (i,p)

                pr = EventReceiver(name, minerva_core, channels)
                pr.start()

                active_processes.append(pr)
                log_client.send_multipart(['DEBUG', 'Starting Receiver %s' % name])
        log_client.send_multipart(['INFO', 'Receiver Processes Started'])
        while True:
            for p in active_processes:
                if not p.is_alive():
                    active_processes.remove(p)
                    p.join()
                    pr = EventReceiver(p.name, minerva_core, channels)
                    p.join()
                    pr.start()
                    active_processes.append(pr)
                    log_client.send_multipart(['ERROR', 'Receiver %s crashed, restarting' % p.name])
            if not pub_listener.is_alive():
                pub_listener.join()
                pub_listener = EventPublisher(minerva_core, channels, cur_config)
                pub_listener.start()
                log_client.send_multipart(['ERROR', 'Receiver Publishing Process crashed, restarting'])
            if not worker_main.is_alive():
                worker_main.join()
                worker_main = Process(name='worker_main', target=worker, args=(minerva_core, cur_config, channels))
                worker_main.start()
                log_client.send_multipart(['ERROR', 'Worker Thread Manager crashed, restarting'])
            if not log_proc.is_alive():
                log_proc.join()
                log_proc = core.MinervaLog(config, channels)
                log_proc.start()
                log_client.send_multipart(['ERROR', 'Logging Process crashed, restarting'])
            time.sleep(1)
    except:
        log_client.send_multipart(['INFO', 'Receiver Processes Shutting down'])
        for p in active_processes:
            p.terminate()
            log_client.send_multipart(['DEBUG', 'Terminating Process %s' % p.name])
        pub_listener.terminate()
        log_client.send_multipart(['DEBUG', 'Terminating Receiver Publishing Process'])
        worker_main.terminate()
        log_client.send_multipart(['DEBUG', 'Terminating Worker Thread Manager'])
        for i in channels['receiver']:
            if os.path.exists(channels['receiver'][i][6:]):
                os.remove(channels['receiver'][i][6:])
        del channels['receiver']
        for i in channels.keys():
            if os.path.exists(channels[i][6:]):
                os.remove(channels[i][6:])
        log_client.send_multipart(['DEBUG', 'Terminating Logging Thread'])
        log_client.send_multipart(['KILL', 'Stop Logger thread'])
        sys.exit()
