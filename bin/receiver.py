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
import minerva
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

def insert_data(cur_config, log_queue):
    client = pymongo.MongoClient()
    alert = client.minerva.alerts
    flow = client.minerva.flow
    alert_events = []
    flow_events = []
    wait_time = time.time()
    count = 0
    while True:
        if not log_queue.empty():
            event = json.loads(log_queue.get())
            timestamp = event['timestamp']
            ts = parse(timestamp)
            tz = timezone('UTC')
            event['timestamp'] = ts.astimezone(tz)
            event['epoch'] = int(time.mktime(ts.timetuple()))
            event['orig_timestamp'] = timestamp
            #print(event)
            if event['logType'] == 'alert':
                alert_events.append(event)
            elif event['logType'] == 'flow':
                flow_events.append(event)
            count += 1
        tdiff = time.time() - wait_time
        if count == 50 or tdiff >= 10:
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
    print(header)
    cert = s.read()
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
def receiver(cur_config, port, log_queue):
    client = pymongo.MongoClient()
    collection = client.minerva.sensors
    print('starting receiver')
    KEYFILE = cur_config['Minerva_Server']['server_private']
    CERTFILE = cur_config['Minerva_Server']['server_cert']
    s = socket(AF_INET, SOCK_STREAM)
    s.bind((cur_config['Minerva_Server']['bindaddr'], int(port)))
    s.listen(1)
    s_ssl = ssl.wrap_socket(s, keyfile=KEYFILE, certfile=CERTFILE, server_side=True, ssl_version=ssl.PROTOCOL_SSLv3)
    while True:
        try:
            print('accepting connections')
            c, a = s_ssl.accept()
            print('Got connection', c, a)
            print(a[0])
            #if int(cur_config['Minerva_Server']['listening_threads']) > 1:
            recv_data(a[0], collection, c, log_queue)
            #else:
                #recv_data(a[0], collection, c, log_queue)
        except Exception as e:
            print('{}: {}'.format(e.__class__.__name__,e))
    
def genKey(cur_config):
    if not os.path.exists(os.path.dirname(cur_config['Minerva_Server']['server_cert'])):
        os.mkdir(os.path.dirname(cur_config['Minerva_Server']['server_cert']))
    if not os.path.exists(os.path.dirname(cur_config['Minerva_Server']['server_private'])):
        os.mkdir(os.path.dirname(cur_config['Minerva_Server']['server_private']))
    key = M2Crypto.RSA.gen_key(1024, 65537)
    key.save_pub_key(cur_config['Minerva_Server']['server_public'])
    key.save_key(cur_config['Minerva_Server']['server_private'], cipher=None)
    pkey = M2Crypto.EVP.PKey()
    pkey.assign_rsa(key)
    cur_time = M2Crypto.ASN1.ASN1_UTCTIME()
    cur_time.set_time(int(time.time()) - 60*60*24)
    expire_time = M2Crypto.ASN1.ASN1_UTCTIME()
    expire_time.set_time(int(time.time()) + 60*60*24*365*10)
    cert = M2Crypto.X509.X509()
    cert.set_pubkey(pkey)
    cs_name = M2Crypto.X509.X509_Name()
    cs_name.C = 'US'
    cs_name.CN = platform.node()
    cert.set_subject(cs_name)
    cert.set_issuer_name(cs_name)
    cert.set_not_before(cur_time)
    cert.set_not_after(expire_time)
    cert.sign(pkey, md="sha256")
    cert.save_pem(cur_config['Minerva_Server']['server_cert'])

def main():
    cur_config = minerva.MinervaConfigs().conf
    if not os.path.exists(cur_config['Minerva_Server']['server_cert']) or not os.path.exists(cur_config['Minerva_Server']['server_private']):
        genKey(cur_config)
    active_processes = []
    log_queue = Queue()
    log_proc = Process(name='logger', target=insert_data, args=(cur_config, log_queue))
    log_proc.start()
    try:
        for p in cur_config['Minerva_Server']['ports']:
    	    pr = Process(name=p, target=receiver, args=((cur_config, p, log_queue)))
            pr.start()
            active_processes.append(pr)
        while True:
            for p in active_processes:
                if not p in active_children():
                    active_processes.remove(p)
                    pr = Process(name=p.name, target=receiver, args=((cur_config, p.name, log_queue)))
                    pr.start()
                    active_processes.append(pr)
            time.sleep(10)
    except:
        for p in active_processes:
            p.terminate()
        sys.exit()
main()
