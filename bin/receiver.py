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


from socket import socket, AF_INET, SOCK_STREAM
import os
from Minerva import core
from multiprocessing import Process, active_children, Queue
import time
import sys
import ssl
import platform
import M2Crypto
import pymongo
import json
from pytz import timezone
from dateutil.parser import parse
import subprocess

def insert_data(config, log_queue):
    db_conf = config['Webserver']['db']
    client = pymongo.MongoClient(db_conf['url'],int(db_conf['port']))
    if db_conf['useAuth']:
        client.minerva.authenticate(db_conf['username'], db_conf['password'])
    alert = client.minerva.alerts
    flow = client.minerva.flow
    alert_events = []
    flow_events = []
    wait_time = time.time()
    count = 0
    count_max = int(config['Event_Receiver']['insertion_batch'])
    wait_max = int(config['Event_Receiver']['insertion_wait'])
    while True:
        if not log_queue.empty():
            event = json.loads(log_queue.get())
            #timestamp = event['timestamp']
            #ts = parse(timestamp)
            #tz = timezone('UTC')
            #event['timestamp'] = ts.astimezone(tz)
            ##make sure epoch is accurate
            #event['epoch'] = int(time.mktime(ts.timetuple()))
            #event['orig_timestamp'] = timestamp
            #print(event)
            if event['logType'] == 'alert':
                timestamp = event['timestamp']
                try:
                    ts = parse(timestamp)
                    tz = timezone('UTC')
                    event['timestamp'] = ts.astimezone(tz)
                    #make sure epoch is accurate
                    event['epoch'] = int(time.mktime(ts.timetuple()))
                except:
                    pass
                event['orig_timestamp'] = timestamp
                alert_events.append(event)
            elif event['logType'] == 'flow':
                event['netflow']['start_epoch'] = time.mktime(parse(event['netflow']['start']).timetuple())
                event['netflow']['stop_epoch'] = time.mktime(parse(event['netflow']['start']).timetuple())
                flow_events.append(event)
            count += 1
        tdiff = time.time() - wait_time
        if count >= count_max or tdiff >= wait_max:
            if len(alert_events) > 0:
                alert.insert(alert_events)
                alert_events = []
            if len(flow_events) > 0:
                flow.insert(flow_events)
                flow_events = []
            count = 0
            wait_time = time.time()
        if not log_queue.empty():
            continue
        else:
            time.sleep(1)
def recv_data(host, collection, s, log_queue):
    header = s.read()
    if header == 'GET_CERT':
        s.send('accept')
        s.close()
        return
    elif header != 'SERVER_AUTH':
        print('bad header: %s' % header)
        s.send('reject')
        s.close()
        return
    cert = s.recv(8192)
    m2cert = M2Crypto.X509.load_cert_string(cert)
    if m2cert.verify(m2cert.get_pubkey()):
        CN = m2cert.get_issuer().get_entries_by_nid(13)[0].get_data().as_text()
    else:
        print('bad cert')
        s.send('reject')
        s.close()
        return
    results = collection.find({ "SERVER": CN, "IP": host })
    print('building results')
    result = []
    for r in results:
        result.append(r)
    print('finished building results')
    if len(result) == 0:
        print('sensor not approved, inserting')
        collection.insert({ "time_created": time.time(), "last_modified": time.time(), "SERVER": CN, "cert": cert, "IP": host, "STATUS": "NOT_APPROVED" })
        s.send('reject')
        s.close()
        return
    elif len(result) > 1:
        print('More than one entry exists %s, %s' % (CN, host))
        s.send('reject')
        s.close()
        return
    elif result[0]['cert'] != cert:
        print('cert changed')
        collection.update({ "SERVER": CN, "IP": host}, { "$set": { "cert": cert, "STATUS": "CERT_CHANGED", "last_modified": time.time() }})
        s.send('reject')
        s.close()
        return
    elif result[0]['STATUS'] != "APPROVED":
        print('sensor not approved')
        s.send('reject')
        s.close()
        return
    else:
        s.send('accept')
    json_data = ''
    while True:
        data = s.recv(8192)
        if data == b'END_EVENT':
            log_queue.put(json_data)
            json_data = ''
        elif data == b'END':
            break
        else:
            json_data = json_data + data
    s.send('accept')
    s.close()
def receiver(cur_config, pname, log_queue):
    ip, port = pname.split('-')
    client = pymongo.MongoClient()
    collection = client.minerva.sensors
    print('starting receiver')
    KEYFILE = cur_config['certs']['private_key']
    CERTFILE = cur_config['certs']['server_cert']
    s = socket(AF_INET, SOCK_STREAM)
    s.bind((ip, int(port)))
    s.listen(1)
    s_ssl = ssl.wrap_socket(s, keyfile=KEYFILE, certfile=CERTFILE, server_side=True, ssl_version=ssl.PROTOCOL_SSLv3)
    active_recv = []
    while True:
        try:
            for p in active_recv:
                if p not in active_children():
                    p.join()
                    active_recv.remove(p)
            if len(active_children()) < int(cur_config['listen_ip'][ip]['receive_threads']):
                print('accepting connections')
                c, a = s_ssl.accept()
                print('Got connection', c, a)
                pr = Process(target=recv_data, args=((a[0], collection, c, log_queue)))
                pr.start()
                active_recv.append(pr)
                #recv_data(a[0], collection, c, log_queue)
            else:
                print('sleeping')
                time.sleep(.001)
        except Exception as e:
            print('{}: {}'.format(e.__class__.__name__,e))
    
def genKey(cur_config):
    if not os.path.exists(os.path.dirname(cur_config['certs']['server_cert'])):
        os.mkdir(os.path.dirname(cur_config['certs']['server_cert']))
    if not os.path.exists(os.path.dirname(cur_config['certs']['private_key'])):
        os.mkdir(os.path.dirname(cur_config['certs']['private_key']))
    cmd = [ 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', cur_config['certs']['private_key'], '-out', cur_config['certs']['server_cert'], '-days', '3650', '-nodes', '-batch', '-subj', '/CN=%s' % platform.node() ]
    subprocess.call(cmd)

def main():
    config = core.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')).conf
    cur_config = config['Event_Receiver']
    if not os.path.exists(cur_config['certs']['server_cert']) or not os.path.exists(cur_config['certs']['private_key']):
        genKey(cur_config)
    active_processes = []
    log_queue = Queue()
    log_procs = []
    for lp in range(0,int(cur_config['insertion_threads'])):
        log_proc = Process(name='logger' + str(lp), target=insert_data, args=(config, log_queue))
        log_proc.start()
        log_procs.append(log_proc)
    try:
        for i in cur_config['listen_ip']:
            for p in cur_config['listen_ip'][i]['ports']:
                name = "%s-%s" % (i,p)
    	        pr = Process(name=name, target=receiver, args=((cur_config, name, log_queue)))
                pr.start()
                active_processes.append(pr)
        while True:
            for p in active_processes:
                if not p in active_children():
                    active_processes.remove(p)
                    pr = Process(name=p.name, target=receiver, args=((cur_config, p.name, log_queue)))
                    pr.start()
                    active_processes.append(pr)
            for lp in log_procs:
                if not lp in active_children():
                    log_procs.remove(lp)
                    log_proc = Process(name=lp.name, target=insert_data, args=(config, log_queue))
                    log_proc.start()
                    log_procs.append(log_proc)
            time.sleep(10)
    except:
        for p in active_processes:
            p.terminate()
        sys.exit()
main()
