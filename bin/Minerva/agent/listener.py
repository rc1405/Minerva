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
import sys

class AgentSubscriber(object):
    def __init__(self, cur_config, minerva_core, channels):
        self.config = cur_config
        self.channels = channels
        self.logger = minerva_core.get_socket(channels)

    def listen(self):
        context = zmq.Context()
        receiver = context.socket(zmq.SUB)
        receiver.identity = self.config['sensor_name']
        receiver.setsockopt(zmq.SUBSCRIBE, self.config['sensor_name'])

        for r in self.config['subscriptions'].keys():
            self.logger.send_multipart(['DEBUG', "Agent listening for messages on tcp://%s:%s" % (r, self.config['subscriptions'][r])])
            #print("connected to %s %s" % ( r, p))
            receiver.connect('tcp://%s:%s' % (r, self.config['subscriptions'][r]))

        workers = context.socket(zmq.PUSH)
        workers.bind(self.channels['worker'])
        self.logger.send_multipart(['DEBUG', "Agent Starting socket for workers"])

        try:
            #zmq.proxy(receiver, workers)
            while True:
                msg = receiver.recv_multipart()
                #print(msg)
                workers.send_multipart(msg)
            receiver.close()
            workers.close()
        except Exception as e:
            print('{}: {}'.format(e.__class__.__name__,e))
            receiver.close()
            self.logger.send_multipart(['DEBUG', "Agent Subscriber shutting down"])
            sys.exit()

class AgentPublisher(object):
    def __init__(self, cur_config, minerva_core, channels):
        self.config = cur_config
        self.channels = channels
        self.core = minerva_core
        self.logger = minerva_core.get_socket(channels)
        self.SRVKEY = False
        self.SRV_string = False
        self.AESKEY = False
        self.PUBCERT = open(cur_config['client_cert'],'r').read()
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(open(cur_config['client_private'],'r').read()))
        self.event_thres = int(cur_config['send_batch'])
        self.time_thres = int(cur_config['send_wait'])
        self.fail_wait = int(cur_config['fail_wait'])

    def publish(self):
        self.logger = self.core.get_socket(self.channels)
        context = zmq.Context()
        sender = context.socket(zmq.PUSH)
        sender.identity = self.config['sensor_name']
        poll = zmq.Poller()
        #poll.register(sender, zmq.POLLIN)

        for r in self.config['publishers'].keys():
            for p in self.config['publishers'][r]:
                self.logger.send_multipart(['DEBUG', "Agent connected to receiver at tcp://%s:%s" % (r, p)])
                sender.connect('tcp://%s:%s' % (r, p))

        worker = context.socket(zmq.PULL)
        worker.bind(self.channels['pub'])
        poll.register(worker, zmq.POLLIN)
        self.logger.send_multipart(['DEBUG', "Agent publisher listening for workers"])

        workpub = context.socket(zmq.PUB)
        workpub.bind(self.channels['worker-pub'])
        self.logger.send_multipart(['DEBUG', "Worker publisher listening for workers"])

        event_transport = context.socket(zmq.REP)
        event_transport.bind(self.channels['events'])
        poll.register(event_transport, zmq.POLLIN)
        self.logger.send_multipart(['DEBUG', "Agent publisher listening for events"])

        event_waiting = False
        events = []

        while True:
            print('sending auth')
            sender.send_multipart([self.config['sensor_name'], json.dumps({
                "_function": "auth",
                "_cert": self.PUBCERT
            })])
            print('receiving auth')
            msg = worker.recv_json()
            print('auth received')
            print(msg)
            try:
                if msg['_function'] == 'auth':
                    try:
                        self.logger.send_multipart(['DEBUG', "Agent publisher received auth reply from receiver"])
                        self.AESKEY = msg['AESKEY'].strip().decode('base64')
                        self.logger.send_multipart(['DEBUG', "Agent publisher successfully decrypted auth key"])
                        workpub.send_json({"_function": "AESKEY", "key": msg['AESKEY'].strip()})
                        break
                    except KeyError:
                           self.logger.send_multipart(['DEBUG', "Agent publisher received error decoding auth reply"])
                           continue
                else:
                    self.logger.send_multipart(['DEBUG', "Agent publisher is not authorized for other functions yet"])
                    continue

            except KeyError:
                self.logger.send_multipart(['DEBUG', "Agent publisher received error processing auth reply"])
                continue

        last_sent = int(time.time())
        worker_count = 0
        sending_pcap = False

        try:
            print('start loop')
            while True:
               sockets = dict(poll.poll(100))
               if event_transport in sockets:
                   self.logger.send_multipart(['DEBUG', "Agent publisher received event from log tailer"])
                   event = event_transport.recv()
                   worker_count += 1
                   events.append(event)
                   if not event_waiting:
                       event_transport.send("success")
                       worker_count -= 1
               if len(events) > self.event_thres or (int(time.time()) - last_sent > self.time_thres and len(events) > 0):
                   if not event_waiting and self.AESKEY:
                       self.logger.send_multipart(['DEBUG', "Agent publisher sending %i events to receivers" % len(events)])
                       sender.send_multipart([self.config['sensor_name'], json.dumps({
                         "_payload": self._encrypt_aes(json.dumps({
                           "_function": "events",
                           "events": events
                         })),
                         "_cert": self.PUBCERT
                       })])
                       event_waiting = True
                       last_sent = int(time.time())
                   if not self.AESKEY:
                       sender.send_multipart([self.config['sensor_name'], json.dumps({
                           "_function": "auth",
                           "_cert": self.PUBCERT
                       })])
               if event_waiting and int(time.time()) - last_sent > self.fail_wait:
                   event_waiting = False

               if worker in sockets:
                   msg = worker.recv_json()
                   if msg['_function'] == 'PCAP':
                       self.logger.send_multipart(['DEBUG', "Agent publisher received PCAP reply for %s" % str(msg['console'])])
                       sender.send_multipart([self.config['sensor_name'], json.dumps({
                           "_payload": self._encrypt_aes(json.dumps({
                               "_function": "PCAP",
                               "console": msg['console'],
                               "payload": msg['payload'],
                               "_action": "reply",
                               "request_id": msg['request_id']
                           })),
                           "_cert": self.PUBCERT,
                       })])
                       sending_pcap = True
                   elif msg['_function'] == 'AESKEY':
                       if self.AESKEY:
                           workpub.send_json({"key": self.AESKEY.encode('base64')})
                           self.logger.send_multipart(['DEBUG', "Agent publisher received AES key requst from worker"])
                           event_waiting = False
                       else:
                           #key_request = True
                           self.logger.send_multipart(['DEBUG', "Agent publisher unable to send AES key to worker"])
                   else:
                       try:
                           if msg['_function'] == 'auth':
                               try:
                                   self.logger.send_multipart(['DEBUG', "Agent publisher received auth request from receiver"])
                                   #aes = self._decrypt_rsa(msg['_message'])
                                   #if aes:
                                   self.AESKEY = msg['AESKEY'].decode('base64')
                                   event_waiting = False
                                   '''



                    elif msg['_function'] == '_PCAPreturn':
                        self.logger.send_multipart(['DEBUG', "Agent worker Sending PCAP status to sender"])
                        publisher.send_json(msg)
                                   
                if workpub in sockets:
                    msg = workpub.recv_json()
                    print(msg)     
                    if msg['_function'] == 'AESKEY':
                        self.AESKEY = msg['key'].decode('base64')
                    elif msg['_function'] == 'PCAP':
                        if msg['_status'] == 'request':
                            if not msg['request_id'] in pcap_requests.keys():
                                pcap_requests[msg['request_id']] = False
                        elif msg['_status'] == 'success':
                            try:   
                                del pcap_requests[msg['request_id']]
                            except KeyError:
                                pass
                        elif msg['_status'] == 'resend':
                            try:   
                                if pcap_requests[msg['request_id']]:
                                    publisher.send_json(pcap_requests[msg['request_id']])
                            except KeyError:
                                pass



                                   NEEDS to be fixed
                                   if sending_pcap:
                                       worker.send_json({"status": "failure", "KEY": aes.strip()})
                                       sending_pcap = False
                                       self.logger.send_multipart(['DEBUG', "Agent publisher received PCAP Faliure, sending new AES Key"])
                                   '''
                                   if self.AESKEY:
                                       #key_request = False
                                       workpub.send_json({"key": self.AESKEY.encode('base64')})
                                       self.logger.send_multipart(['DEBUG', "Agent publisher received AES key requst from worker"])

                               except KeyError:
                                   self.logger.send_multipart(['DEBUG', "Agent publisher sending auth request to receivers"])
                                   sender.send_multipart([self.config['sensor_name'], json.dumps({
                                       "_function": "auth",
                                       "_cert": self.PUBCERT
                                   })])
                           elif msg['_function'] == 'events':
                               print('events!')
                               #TODO Change to ack for events
                               #if sending_pcap:
                                   #receiver.send_json({"status": "success"})
                                   #self.logger.send_multipart(['DEBUG', "Agent publisher received PCAP success"])
                               if msg['status'] == 'success':
                                   print('success')
                                   self.logger.send_multipart(['DEBUG', "Agent publisher received ack on sent events"])
                                   for i in xrange(0, worker_count):
                                       event_transport.send("write checkpoint")
                                       worker_count -= 1
                               event_waiting = False
                               events = []
                               last_sent = int(time.time())

                       except KeyError:
                           denc_msg = json.loads(self._decrypt_rsa(msg['_payload']))
                           if denc_msg['_function'] == 'events':
                               if denc_msg['status'] == 'success':
                                   self.logger.send_multipart(['DEBUG', "Agent publisher received ack on sent events"])
                                   for i in xrange(0, worker_count):
                                       event_transport.send("write checkpoint")
                                       worker_count -= 1
                               event_waiting = False
                               events = []
                               last_sent = int(time.time())

        except Exception as e:
            print(e)
            self.logger.send_multipart(['DEBUG', "Agent publisher shutting down"])
            self.logger.close(linger=1000)
            worker.close(linger=1000)
            workpub.close(linger=1000)
            sender.close(linger=1000)
            sys.exit()


    def _encrypt_rsa(self, payload):
        self.logger.send_multipart(['DEBUG', "Agent publisher RSA encrypting message"])
        enc_payload = self.SRVKEY.public_encrypt(payload, M2Crypto.RSA.pkcs1_padding)
        enc_payload = self.PRIVKEY.private_encrypt(enc_payload, M2Crypto.RSA.pkcs1_padding).encode('base64')
        return enc_payload

    def _encrypt_aes(self, payload):
        #key = uuid.uuid4().hex
        self.logger.send_multipart(['DEBUG', "Agent publisher AES encrypting message"])
        cipher = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=self.AESKEY, iv=self.AESKEY, op=1)
        enc_payload = cipher.update(payload) + cipher.final()
        return enc_payload.encode('base64')

    def _decrypt_rsa(self, enc_payload):
        if enc_payload:
            dmesg = self.PRIVKEY.private_decrypt(enc_payload.decode('base64'), M2Crypto.RSA.pkcs1_padding)
            self.logger.send_multipart(['DEBUG', "Agent publisher decrypting RSA message"])
            return dmesg
        else:
            self.logger.send_multipart(['ERROR', "Agent publisher unale to decrypt RSA message"])
            return False
