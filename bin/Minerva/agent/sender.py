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
import json
import os
import ssl
import sys
import time
from socket import socket, AF_INET, SOCK_STREAM

import M2Crypto
import redis

class EventSender(object):
    def __init__(self, cur_config, event_push):
        self.cur_config = cur_config
        self.event_push = event_push

    def get_server_cert(self):
        server_cert = ssl.get_server_certificate((self.cur_config['target_addr']['destination'], int(self.cur_config['target_addr']['port'])))
        scert = open(self.cur_config['target_addr']['server_cert'],'w')
        scert.writelines(server_cert)
        scert.flush()
        scert.close()
 
    def send_events(self, batch):
        keyfile = self.cur_config['client_private']
        certfile = self.cur_config['target_addr']['server_cert']
        if not os.path.exists(certfile):
            self.get_server_cert()
        cert = open(self.cur_config['client_cert'],'r').read()
        s = socket(AF_INET, SOCK_STREAM)
        s_ssl = ssl.wrap_socket(s, ca_certs=self.cur_config['target_addr']['server_cert'], cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_SSLv3)
        s_ssl.connect((self.cur_config['target_addr']['destination'], int(self.cur_config['target_addr']['port'])))
        s_ssl.send('SERVER_AUTH')
        s_ssl.send(cert)
        response = s_ssl.read()
        if str(response) == 'GET_PORT':
            s_ssl.send(str(self.cur_config['listener']['port']))
            response = s_ssl.read()
        if response == 'reject':
            s_ssl.close()
            return response
        else:
            private_key = M2Crypto.RSA.load_key(keyfile)
            challenge = private_key.private_decrypt(response, M2Crypto.RSA.pkcs1_padding)
            s_ssl.send(challenge)
        response = s_ssl.read()
        if response == 'reject':
            s_ssl.close()
            return response
        if len(batch) > 0:
            for b in batch:
                s_ssl.send(b)
                s_ssl.send('END_EVENT')
            s_ssl.send(b'END')
            server_resp = s_ssl.recv(8192)
            s_ssl.close()
            return server_resp
        s_ssl.close()
        return

    def sender(self):
        if self.cur_config['redis']['enabled']:
            r = redis.Redis(host=self.cur_config['redis']['server'], port=self.cur_config['redis']['port'])
        else:
            queue = self.event_push.queue
        batchsize = int(self.cur_config['target_addr']['send_batch'])
        sendwait = int(self.cur_config['target_addr']['send_wait'])
        key = self.cur_config['redis']['key']
        batch = []
        start_wait = time.time()
        while True:
            try:
                if self.cur_config['redis']['enabled']:
                    if r.llen(key) >= batchsize or (time.time() - start_wait > sendwait and r.llen(key) > 0):
                        events = r.lrange(key,0,batchsize-1)
                        event_ct = len(events)
                        batch = batch + events
                        retval = 'reject'
                        retval = self.send_events(batch)
                        if retval == 'accept':
                            r.ltrim(key, event_ct-1, -1)
                            batch = []
                            start_wait = time.time()
                        else:
                            time.sleep(self.cur_config['target_addr']['fail_sleep'])
                    else:
                        time.sleep(1)
                else:
                    if queue.qsize() >= batchsize or time.time() - start_wait > sendwait:
                        count = 1
                        while True:
                            batch.append(json.dumps(queue.get()))
                            count += 1
                            if count == batchsize:
                                break
                        retval = 'reject'
                        retval = self.send_events(batch)
                        if retval == 'accept':
                            batch = []
                            start_wait = time.time()
                        else:
                            time.sleep(self.cur_config['target_addr']['fail_sleep'])
                    else:
                        time.sleep(1)
            except:
                sys.exit()
    
