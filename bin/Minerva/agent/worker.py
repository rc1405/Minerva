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

import M2Crypto
#from .carver import PCAPCarver
import threading

class AgentWorker(threading.Thread):
    def __init__(self, channels):
        threading.Thread.__init__(self)
        self.channels = channels
        server_cert = M2Crypto.X509.load_cert(str(self.server_cert))
        pub_key = server_cert.get_pubkey()
        rsa_key = pub_key.get_rsa()
        self.PUBCERT = open(cur_config['client_cert'],'r').read()
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(open(cur_config['client_private'],'r').read()))
        self.AESKEY = False

    def run(self):
        context = zmq.Context.instance()

        work = context.socket(zmq.PULL)
        work.connect(self.channels['worker'])

        publisher = context.socket(zmq.PUSH)
        publisher.connect(self.channels['pub'])

        #pcapWorker = PCAPProessor(self.config)

        while True:
            if work.poll(1000):
                msg = work.recv_json()
                try:
                    if msg['_function'] == 'auth':
                        try:
                            key = self._decrypt_rsa(msg['_message'])
                            if key:
                                self.AESKEY = key
                        except KeyError:
                            try:
                                self.AESKEY = msg['_cipher'].decode('base64')
                            except KeyError:
                                publisher.send_json({
                                    "_function": "auth",
                                    "_cert": self.PUBCERT,
                                })
                except KeyError:
                    if self.AESKEY:
                        denc_msg = self_decrypt_aes(msg['_payload'])
                        if denc_msg:
                            elif msg['_function'] == 'PCAP':
                                packets = pcapWorker.process(dmsg['payload'])
                                if packets:
                                    publisher.send_json({
                                        "mid": self.name,
                                        "pubcert": self.PUBCERT,
                                        "_action": "reply",
                                        "payload": {
                                            "payload": packets,
                                            "console": dmsg['console'],
                                            "request_id": msg['request_id']
                                        },
                                        "_function": "PCAP"
                                    })
                                else:
                                    publisher.send_json({
                                        "mid": self.name,
                                        "pubcert": self.PUBCERT,
                                        "_action": "reply",
                                        "payload": {
                                            "payload": "No Packets Found",
                                            "console": dmsg['console'],
                                            "request_id": msg['request_id']
                                        },
                                        "_function": "PCAP"
                                    })

                        else:
                            publisher.send_json({
                                "_function": "auth",
                                "_cert": self.PUBCERT,
                            })
                    else:
                            publisher.send_json({
                                "_function": "auth",
                                "_cert": self.PUBCERT,
                            })

    def _decrypt_aes(self, payload):
        print('trying to decrypt')
        #try:
        if 1 == 1:
            cipher = M2Crypto.EVP.Cipher('aes_256_cbc', key=self.AESKEY, iv=self.AESKEY, op=0)
            denc_msg = json.loads(cipher.update(payload.decode('base64')) + cipher.final())
            return denc_msg
        #except:
            #return False
                          
    def decrypt_options(self, encrypted_options):
        server_cert = M2Crypto.X509.load_cert(str(self.server_cert))
        pub_key = server_cert.get_pubkey()
        rsa_key = pub_key.get_rsa()
        try:
            decrypted_options = json.loads(rsa_key.public_decrypt(encrypted_options, M2Crypto.RSA.pkcs1_padding))
        except:
            return False
        return decrypted_options

class PCAPprocessor(object):
    def __init__(self, config):
        self.config = config
        self.server_cert = config['target_addr']['server_cert']
        self.client_cert = config['client_cert']
        self.client_key = config['client_private']
        #self.carver = PCAPCarver(config)

    def process(self, options):
        if options['request_type'] == 'alert':
            tmp_file = self.carver.parse_alert(src_ip=options['src_ip'], src_port=options['src_port'], dest_ip=options['dest_ip'], dest_port=options['dest_port'], proto=options['proto'], event_time=options['event_time'])
        elif options['request_type'] == 'flow':
            tmp_file = self.carver.parse_flow(src_ip=options['src_ip'], src_port=options['src_port'], dest_ip=options['dest_ip'], dest_port=options['dest_port'], proto=options['proto'], start_time=options['start_time'], end_time=options['end_time'])
            
        if tmp_file == 'No Packets Found':
            return False

        tmp_file.seek(0)
        b64_pcap = tmp_file.read().encode('base64')
        tmp_file.close()
        return b64_pcap
