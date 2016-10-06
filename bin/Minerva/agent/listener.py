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

import time
import json
import uuid
import zmq
import M2Crypto

class AgentSubscriber(object):
    def __init__(self, cur_config, channels):
        self.config = cur_config
        self.channels = channels

    def listen(self):
        context = zmq.Context()
        receiver = context.socket(zmq.SUB)
        #add subscribe
        receiver.identity = self.config['sensor_name']
        receiver.setsockopt(zmq.SUBSCRIBE, self.config['sensor_name'])
        #receiver.setsockopt(zmq.SUBSCRIBE,"")

        for r in self.config['listeners'].keys():
            for p in self.config['listeners'][r]:
                print("connected to %s %s" % ( r, p))
                receiver.connect('tcp://%s:%s' % (r, p))

        workers = context.socket(zmq.PUSH)
        workers.bind(self.channels['worker'])

        try:
            zmq.proxy(receiver, workers)
            server.close()
            workers.close()
        except:
            server.close()

class AgentPublisher(object):
    def __init__(self, cur_config, channels):
        self.config = cur_config
        self.channels = channels
        self.SRVKEY = False
        self.SRV_string = False
        self.AESKEY = False
        self.PUBCERT = open(cur_config['client_cert'],'r').read()
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(open(cur_config['client_private'],'r').read()))
        self.event_thres = int(cur_config['send_batch'])
        self.time_thres = int(cur_config['send_wait'])

    def publish(self, worker_lock):
        worker_lock.acquire()
        context = zmq.Context()
        sender = context.socket(zmq.DEALER)
        sender.identity = self.config['sensor_name']
        poll = zmq.Poller()
        poll.register(sender, zmq.POLLIN)

        for r in self.config['destinations'].keys():
            sender.connect('tcp://%s:%s' % (r, self.config['destinations'][r]))

        receiver = context.socket(zmq.REP)
        receiver.bind(self.channels['pub'])
        poll.register(receiver, zmq.POLLIN)

        event_transport = context.socket(zmq.REP)
        event_transport.bind(self.channels['events'])
        poll.register(event_transport, zmq.POLLIN)

        event_waiting = False
        events = []

        sender.send_json({
            "_function": "auth",
            "_cert": self.PUBCERT
        })
        msg = sender.recv_json()
        server_cert = M2Crypto.X509.load_cert_string(str(msg['_cert']))
        pub_key = server_cert.get_pubkey()
        rsa_key = pub_key.get_rsa()
        self.SRVKEY = rsa_key
        AESKEY = self._decrypt_rsa(msg['_message'])
        if AESKEY:
            self.AESKEY = AESKEY.decode('base64')

        #print('done getting auth')
        worker_lock.release()
        last_sent = int(time.time())
        worker_count = 0
        sending_pcap = False

        while True:
           sockets = dict(poll.poll(100))
           if event_transport in sockets:
           #if event_transport.poll(1):
               #print('have event')
               event = event_transport.recv()
               worker_count += 1
               events.append(event)
               if not event_waiting:
                   #print('returning event')
                   event_transport.send("success")
                   worker_count -= 1
           #if len(events) > self.event_thres or int(time.time()) - last_sent > self.time_thres:
           if len(events) > self.event_thres or (int(time.time()) - last_sent > self.time_thres and len(events) > 0):
               #encrypt payload
               #if not self.SRVKEY:
                   #sender.send_json({
                       #"_function": "auth",
                       #"_cert": self.PUBCERT
                   #})
                   #msg = sender.recv_json()
                   #server_cert = M2Crypto.X509.load_cert_string(str(msg['_cert']))
                   #pub_key = server_cert.get_pubkey()
                   #rsa_key = pub_key.get_rsa()
                   #self.SRVKEY = rsa_key
                   #self.AESKEY = self._decrypt_rsa(msg['_message'])

               #if not event_waiting or wait_time > other_time:
               if not event_waiting and self.AESKEY:
                   print('sending event to receiver')
                   sender.send_json({
                     "_payload": self._encrypt_aes(json.dumps({
                       "_function": "events",
                       "events": events
                     })),
                     "_cert": self.PUBCERT
                   })
                   event_waiting = True
               if not self.AESKEY:
                   sender.send_json({
                       "_function": "auth",
                       "_cert": self.PUBCERT
                   })

           if sender in sockets:
           #if sender.poll(1):
               #print('received sendor stuff')
               msg = sender.recv_json()
               #print(msg)
               try:
                   if msg['_function'] == 'auth':
                       server_cert = M2Crypto.X509.load_cert_string(str(msg['_cert']))
                       pub_key = server_cert.get_pubkey()
                       rsa_key = pub_key.get_rsa()
                       self.SRVKEY = rsa_key
                       try:
                           aes = self._decrypt_rsa(msg['_message'])
                           if aes:
                               self.AESKEY = aes.strip().decode('base64')
                           event_waiting = False
                           if sending_pcap:
                               receiver.send_json({"status": "failure", "KEY": aes.strip()})
                               sending_pcap = False
                       except KeyError:
                           print('reauth')
                           sender.send_json({
                               "_function": "auth",
                               "_cert": self.PUBCERT
                           })
                   elif msg['_function'] == 'ack':
                       if sending_pcap:
                           receiver.send_json({"status": "success"})
               except KeyError:
                   print('no _function')
                   denc_msg = json.loads(self._decrypt_rsa(msg['_payload']))
                   if denc_msg['_function'] == 'events':
                       print('resetting events')
                       if denc_msg['status'] == 'success':
                           print('resetting events')
                           for i in xrange(0, worker_count):
                               event_transport.send("write checkpoint")
                               worker_count -= 1
                       event_waiting = False
                       events = []
                       last_sent = int(time.time())

           if receiver in sockets:
           #if receiver.poll(1):
               msg = receiver.recv_json()
               if msg['_function'] == 'PCAP':
                   sender.send_json({
                       "_payload": self._encrypt_aes(json.dumps({
                           "_function": "PCAP", 
                           "console": msg['console'],
                           "payload": msg['payload'],
                           "_action": "reply",
                           "request_id": msg['request_id']
                       })),
                       "_cert": self.PUBCERT,
                   })
                   sending_pcap = True
               elif msg['_function'] == 'AESKEY':
                   receiver.send_json({"key": self.AESKEY.encode('base64')})


    def _encrypt_rsa(self, payload):
        enc_payload = self.SRVKEY.public_encrypt(payload, M2Crypto.RSA.pkcs1_padding)
        enc_payload = self.PRIVKEY.private_encrypt(enc_payload, M2Crypto.RSA.pkcs1_padding).encode('base64')
        return enc_payload

    def _encrypt_aes(self, payload):
        #key = uuid.uuid4().hex
        cipher = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=self.AESKEY, iv=self.AESKEY, op=1)
        enc_payload = cipher.update(payload) + cipher.final()
        return enc_payload.encode('base64')

    def _decrypt_rsa(self, enc_payload):
        if enc_payload:
            dmesg = self.PRIVKEY.private_decrypt(enc_payload.decode('base64'), M2Crypto.RSA.pkcs1_padding)
            return dmesg
        else:
            return False

