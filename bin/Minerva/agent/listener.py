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
        receiver.identity = self.config['sensor_name']
        receiver.setsockopt(zmq.SUBSCRIBE, self.config['sensor_name'])

        for r in self.config['listeners'].keys():
            for p in self.config['listeners'][r]:
                print("connected to %s %s" % ( r, p))
                receiver.connect('tcp://%s:%s' % (r, p))

        workers = context.socket(zmq.PUSH)
        workers.bind(self.channels['worker'])

        while True:
            try:
                if receiver.poll(1000):
                    msg = receiver.recv_multipart()
                    workers.send(msg[1])
            except Exception as e:
                print('{}: {}'.format(e.__class__.__name__,e))
                continue

class AgentPublisher(object):
    def __init__(self, cur_config, channels):
        self.config = cur_config
        self.channels = channels
        self.SRVKEY = False
        self.AESKEY = False
        self.PUBCERT = open(cur_config['client_cert'],'r').read()
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(open(cur_config['client_private'],'r').read()))
        self.event_thres = int(cur_config['send_batch'])
        self.time_thres = int(cur_config['send_wait'])
        self.fail_thres = int(cur_config['fail_wait'])

    def _get_receiver_socket(self, context):
        sender = context.socket(zmq.DEALER)
        sender.identity = self.config['sensor_name']

        for r in self.config['destinations'].keys():
            sender.connect('tcp://%s:%s' % (r, self.config['destinations'][r]))
    
        return sender

    def publish(self, worker_lock):
        worker_lock.acquire()
        context = zmq.Context()
        #sender = context.socket(zmq.DEALER)
        #sender.identity = self.config['sensor_name']
        sender = self._get_receiver_socket(context)

        poll = zmq.Poller()
        poll.register(sender, zmq.POLLIN)

        #for r in self.config['destinations'].keys():
            #sender.connect('tcp://%s:%s' % (r, self.config['destinations'][r]))

        receiver = context.socket(zmq.PULL)
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

        worker_lock.release()
        last_sent = int(time.time())
        last_fail = int(time.time())
        worker_count = 0

        while True:
           sockets = dict(poll.poll(100))
           if event_transport in sockets:
               event = event_transport.recv()
               worker_count += 1
               events.append(event)
               if not event_waiting:
                   event_transport.send("success")
                   worker_count -= 1
           if len(events) > self.event_thres or (int(time.time()) - last_sent > self.time_thres and len(events) > 0):
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
                   last_fail = int(time.time())
               if not self.AESKEY:
                   sender.send_json({
                       "_function": "auth",
                       "_cert": self.PUBCERT
                   })
           if event_waiting and self.AESKEY and (int(time.time())-last_fail > self.fail_thres):
               poll.unregister(sender)
               sender = self._get_receiver_socket(context)
               poll.register(sender, zmq.POLLIN)
               event_waiting = False

           if sender in sockets:
               msg = sender.recv_json()
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
                       except KeyError:
                           sender.send_json({
                               "_function": "auth",
                               "_cert": self.PUBCERT
                           })
               except KeyError:
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
               msg = receiver.recv_json()
               if msg['_function'] == 'PCAP':
                   sender.send_json({
                       "_payload": self._encrypt_aes(json.dumps({
                           "_function": "PCAP", 
                           "console": msg['console'],
                           "payload": msg['payload'],
                           "action": "reply",
                           "request_id": msg['request_id']
                       })),
                       "_cert": self.PUBCERT,
                   })


    def _encrypt_rsa(self, payload):
        enc_payload = self.SRVKEY.public_encrypt(payload, M2Crypto.RSA.pkcs1_padding)
        enc_payload = self.PRIVKEY.private_encrypt(enc_payload, M2Crypto.RSA.pkcs1_padding).encode('base64')
        return enc_payload

    def _encrypt_aes(self, payload):
        cipher = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=self.AESKEY, iv=self.AESKEY, op=1)
        enc_payload = cipher.update(payload) + cipher.final()
        return enc_payload.encode('base64')

    def _decrypt_rsa(self, enc_payload):
        if enc_payload:
            dmesg = self.PRIVKEY.private_decrypt(enc_payload.decode('base64'), M2Crypto.RSA.pkcs1_padding)
            return dmesg
        else:
            return False

