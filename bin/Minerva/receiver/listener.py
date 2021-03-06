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
from multiprocessing import Process

class EventReceiver(Process):
    def __init__(self, pname, minerva_core, channels):
        Process.__init__(self)
        self.channels = channels
        self.minerva_core = minerva_core
        self.pname = pname

    def run(self):
        context = zmq.Context()
        log_client = self.minerva_core.get_socket(self.channels)
        log_client.send_multipart(['DEBUG','Starting Event Listener %s' % self.pname])
        ip, port = self.pname.split('-')

        server = context.socket(zmq.PULL)
        server.bind('tcp://%s:%s' % (ip, port))
        log_client.send_multipart(['DEBUG', "Receiver listening for messages on tcp://%s:%s" % (ip, port)])

        workers = context.socket(zmq.PUSH)
        log_client.send_multipart(['DEBUG', "Receiver binded workers to %s" % self.channels['receiver']["%s-%s" % (ip, port)]])
        workers.bind(self.channels['receiver']["%s-%s" % (ip, port)])

        log_client.send_multipart(['INFO', "Receiver listening for events"])

        try:
            zmq.proxy(server, workers)
            server.close()
            workers.close()
        except:
            server.close()
            workers.close()

        log_client.send_multipart(['INFO', "Receiver %s shutting down" % self.pname])

class EventPublisher(Process):
    def __init__(self, minerva_core, channels, cur_config):
        Process.__init__(self)
        db = minerva_core.get_db()
        self.logger = minerva_core.get_socket(channels)
        self.core = minerva_core
        #TODO Update CERTS
        self.certs = db.certs
        self.channels = channels
        self.config = cur_config
        self.keys = db.keys
        keys = db.certs.find_one({"type": "receiver"})
        webcert = db.certs.find_one({"type": "webserver"})
        if webcert:
            webcert = M2Crypto.X509.load_cert_string(str(webcert['CERT']))
            pubkey = webcert.get_pubkey()
            self.WEBKEY = pubkey.get_rsa()
        else:
            self.WEBKEY = False
        key = keys['key']
        self.PUBCERT = keys['cert']
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(key))

    def _encrypt_aes(self, target, payload, key=None):
        if key is None:
            aeskey = self.keys.find_one({"SERVER": target.split('|-_')[0]})
            if aeskey:
                aeskey = aeskey['KEY'].decode('base64')
            else:
                self.logger.send_multipart(['ERROR','Publisher Failed to find AES Key for %s' % target])
                return False
        else:
            aeskey = key
        cipher = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=aeskey, iv=aeskey, op=1)
        enc_payload = cipher.update(payload) + cipher.final()
        self.logger.send_multipart(['DEBUG','Publisher AES Encrypted Message for %s' % target])
        return enc_payload.encode('base64')

    def _encrypt_rsa(self, payload):
        if self.WEBKEY:
            enc_payload = self.WEBKEY.public_encrypt(payload, M2Crypto.RSA.pkcs1_padding).encode('base64')
            self.logger.send_multipart(['DEBUG','Publisher RSA Encrypted Message'])
            return enc_payload
        else:
            self.logger.send_multipart(['ERROR','Publisher Unable to encrypt RSA'])
            return False

    def run(self):

        db = self.core.get_db()
        self.certs = db.certs
        self.keys = db.keys
        keys = db.certs.find_one({"type": "receiver"})
        webcert = db.certs.find_one({"type": "webserver"})
        if webcert:
            webcert = M2Crypto.X509.load_cert_string(str(webcert['CERT']))
            pubkey = webcert.get_pubkey()
            self.WEBKEY = pubkey.get_rsa()
        else:
            self.WEBKEY = False
        key = keys['key']
        self.PUBCERT = keys['cert']
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(key))
        self.logger = self.core.get_socket(self.channels)
        context = zmq.Context()
        sender = context.socket(zmq.PUB)

        for r in self.config['listen_ip'].keys():
            self.logger.send_multipart(['DEBUG','Starting Publisher on tcp://%s:%s' % (r, str(self.config['listen_ip'][r]['pub_port']))])
            sender.bind('tcp://%s:%s' % (r, str(self.config['listen_ip'][r]['pub_port'])))

        receiver = context.socket(zmq.PULL)
        receiver.bind(self.channels['pub'])
        self.logger.send_multipart(['DEBUG','Publisher now listening for events from workers'])
 
        event_queue = []

        try:
            while True:
                if receiver.poll(500):
                    ID, msg = receiver.recv_multipart()
                    msg = json.loads(msg)
                    try:
                        if msg['_function'] == 'PCAP':
                            try:
                                if msg['_payload']['action'] == "request":
                                    self.logger.send_multipart(['DEBUG','Publisher Received PCAP Request for %s' % ID])
                                    payload = {
                                        "_function": "PCAP",
                                        "action": "request",
                                        "console": msg['_payload']['console'],
                                        "request_id": msg['_payload']['request_id'],
                                        "request": msg['_payload']['request']
                                    }
                                    enc_payload = self._encrypt_aes(ID, json.dumps(payload))
                                    if enc_payload:
                                        sender.send_multipart([ID, json.dumps({
                                            "mid": ID,
                                            "_payload": enc_payload
                                        })])
                                    else:
                                        self.logger.send_multipart(['DEBUG','Publisher Unable to encrypt request for %s, sending reauth' % ID])
                                        event_queue.append([msg['mid'], payload])
                                        sender.send_multipart([ID, json.dumps({
                                            "mid": msg['mid'],
                                            "_function": "auth",
                                            "_cert": self.PUBCERT
                                        })])
                            except TypeError:
                                self.logger.send_multipart(['DEBUG','Publisher Received PCAP Reply for %s' % str(msg['mid'])])
                                sender.send_multipart([str(msg['mid']), json.dumps(msg)])
                        elif msg['_function'] == 'auth':
                            self.logger.send_multipart(['DEBUG','Sending Auth for %s' % str(ID)])
                            sender.send_multipart([ID, json.dumps(msg)])
                    except KeyError:
                        sender.send_multipart([ID, json.dumps(msg)])
                    
                if len(event_queue) > 0:
                    for e in event_queue:
                        enc_payload = self._encrypt_aes(str(e[0]), json.dumps(e[1]))
                        if enc_payload:
                            self.logger.send_multipart(['DEBUG','Publisher Reauth success, sending message to %s' % str(e[0])])
                            sender.send_multipart([str(e[0]), json.dumps({
                                "mid": e[0],
                                "_payload": enc_payload
                            })])
                            event_queue.remove(e)
        except Exception as e:
            #print('{}: {}'.format(e.__class__.__name__,e))

            sender.close()
            receiver.close()
            self.logger.send_multipart(['INFO', "Publisher is shutting down"])
