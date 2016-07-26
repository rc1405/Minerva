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


#from socket import socket, AF_INET, SOCK_STREAM
import zmq
import M2Crypto

import time
import json
import os

class EventReceiver(object):
    def __init__(self, worker_lock, channels):
        self.worker_lock = worker_lock
        self.channels = channels
        self.channels['context'] = zmq.Context()

    def listen(self, pname):
        ip, port = pname.split('-')
        server = self.channels['context'].socket(zmq.ROUTER)
        server.bind('tcp://%s:%s' % (ip, port))

        workers = self.channels['context'].socket(zmq.DEALER)
        print("binded to %s" % self.channels['receiver']["%s-%s" % (ip, port)])
        workers.bind(self.channels['receiver']["%s-%s" % (ip, port)])

        try:
            zmq.proxy(server, workers)
            server.close()
            workers.close()
        except:
            server.close()
            workers.close()

class EventPublisher(object):
    def __init__(self, minerva_core, channels, cur_config):
        db = minerva_core.get_db()
        #TODO Update CERTS
        self.certs = db.certs
        self.channels = channels
        self.config = cur_config
        self.channels['context'] = zmq.Context()
        self.keys = db.keys
        keys = db.certs.find_one({"type": "receiver"})
        webcert = db.certs.find_one({"type": "webserver"})
        if webcert:
            webcert = M2Crypto.X509.load_cert_string(str(webcert['cert']))
            pubkey = webcert.get_pubkey()
            self.WEBKEY = pubkey.get_rsa()
        else:
            self.WEBKEY = False
        key = keys['key']
        self.PUBCERT = keys['cert']
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(key))

    def _encrypt_aes(self, target, payload, key=None):
        if key is None:
            aeskey = self.keys.find_one({"SERVER": target})
            if aeskey:
                aeskey = aeskey['KEY'].decode('base64')
            else:
                return False
        else:
            aeskey = key
        cipher = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=aeskey, iv=aeskey, op=1)
        enc_payload = cipher.update(payload) + cipher.final()
        return enc_payload.encode('base64')

    def _encrypt_rsa(self, payload):
        if self.WEBKEY:
            enc_payload = self.WEBKEY.public_encrypt(payload, M2Crypto.RSA.pkcs1_padding).encode('base64')
            return enc_payload
        else:
            return False

    def publish(self):
        sender = self.channels['context'].socket(zmq.PUB)

        for r in self.config['listen_ip'].keys():
            print('connected to %s %s' % ( r, str(self.config['listen_ip'][r]['pub_port'])))
            sender.bind('tcp://%s:%s' % (r, str(self.config['listen_ip'][r]['pub_port'])))

        #sender.bind('tcp://%s:%s' % (ip, port))

        receiver = self.channels['context'].socket(zmq.PULL)
        receiver.bind(self.channels['pub'])
 
        event_queue = []

        try:
            while True:
                if receiver.poll(500):
                    print('have message')
                    msg = receiver.recv_json()
                    if msg['_payload']['action'] == "request":
                        payload = {
                            "_function": "PCAP",
                            "action": "request",
                            "console": msg['_payload']['console'],
                            "request_id": msg['_payload']['request_id'],
                            "request": msg['_payload']['request']
                        }
                        enc_payload = self._encrypt_aes(msg['mid'], json.dumps(payload))
                        if enc_payload:
                            print('request sent')
                            sender.send_multipart([str(msg['mid']), json.dumps({
                                "mid": msg['mid'],
                                "_payload": enc_payload
                            })])
                        else:
                            event_queue.append([msg['mid'], payload])
                            sender.send_multipart([str(msg['mid']), json.dumps({
                                "mid": msg['mid'],
                                "_function": "auth",
                                "_cert": self.PUBCERT
                            })])
                    elif msg['_payload']['action'] == "reply":
     
                        key = os.urandom(32)
                        cipher = self._encrypt_rsa(key)
                        if cipher:
                            sender.send_multipart([str(msg['payload']['console']), json.dumps({
                                "mid": msg['payload']['console'],
                                "_cipher": cipher,
                                "_payload": self_encrypt_aes(msg['_payload']['console'], json.dumps(msg['_payload']), key=key)
                            })])
                if len(event_queue) > 0:
                    for e in event_queue:
                        enc_payload = self._encrypt_aes(e[0], json.dumps(e[1]))
                        if enc_payload:
                            sender.send_multipart([str(e[0]), json.dumps({
                                "mid": e[0],
                                "_payload": enc_payload
                            })])
                            event_queue.remove(e)
        except:
            sender.close()
            receiver.close()
