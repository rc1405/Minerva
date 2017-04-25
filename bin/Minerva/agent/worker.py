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
import zmq
import sys

import M2Crypto
from .carver import PCAPCarver

class AgentWorker(object):
    def __init__(self, cur_config, minerva_core, channels):
        self.channels = channels
        self.config = cur_config
        self.core = minerva_core
        self.logger = minerva_core.get_socket(channels)
        self.AESKEY = False
        self.SRVKEY = False
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(open(cur_config['client_private'],'r').read()))

    def _decrypt_aes(self, payload):
        try:
            cipher = M2Crypto.EVP.Cipher('aes_256_cbc', key=self.AESKEY, iv=self.AESKEY, op=0)
            events = json.loads(cipher.update(payload.decode('base64')) + cipher.final())
            self.logger.send_multipart(['DEBUG', "Agent worker decrypted AES message"])
            return events
        except Exception as e:
            #print('{}: {}'.format(e.__class__.__name__,e))
            self.logger.send_multipart(['ERROR', "Agent worker unable to decrypt AES message"])
            return False

    def _decrypt_rsa(self, enc_payload):
        if enc_payload:
            dmesg = self.PRIVKEY.private_decrypt(enc_payload.decode('base64'), M2Crypto.RSA.pkcs1_padding)
            self.logger.send_multipart(['DEBUG', "Agent publisher decrypting RSA message"])
            return json.loads(dmesg)
        else:
            self.logger.send_multipart(['ERROR', "Agent publisher unable to decrypt RSA message"])
            return False


    def start(self):
        self.logger = self.core.get_socket(self.channels)
        context = zmq.Context.instance()

        work = context.socket(zmq.PULL)
        work.connect(self.channels['worker'])
        self.logger.send_multipart(['DEBUG', "Agent worker listening for events"])

        publisher = context.socket(zmq.PUSH)
        publisher.connect(self.channels['pub'])
        self.logger.send_multipart(['DEBUG', "Agent worker connected to publisher"])

        workpub = context.socket(zmq.SUB)
        workpub.connect(self.channels['worker-pub'])
        self.logger.send_multipart(['DEBUG', "Agent worker connected to internal pub/sub"])
        workpub.identity = self.config['sensor_name']
        workpub.setsockopt(zmq.SUBSCRIBE, "")

        poll = zmq.Poller()
        poll.register(work, zmq.POLLIN)
        poll.register(workpub, zmq.POLLIN)

        pcapWorker = PCAPprocessor(self.config)

        try:
            while True:
                sockets = dict(poll.poll(100))
                if work in sockets:
                    sensor, msg = work.recv_multipart()
                    msg = json.loads(msg)
                    self.logger.send_multipart(['DEBUG', "Agent worker received work task"])
                    if '_payload' in msg.keys():
                        msg = self._decrypt_aes(msg['_payload'])
                        if not msg:
                            self.logger.send_multipart(['DEBUG', "Agent worker requesting new AES key"])
                            continue
                    elif '_message' in msg.keys():
                        msg = self._decrypt_rsa(msg['_message'])
                        if not msg:
                            self.logger.send_multipart(['DEBUG', "Agent worker requesting new AES key"])
                            continue

                    if msg['_function'] == 'PCAP':
                        self.logger.send_multipart(['DEBUG', "Agent worker received PCAP Request"])
                        packets = pcapWorker.process(msg['request'])
                        attempts = 0
                        while True:
                            if packets:
                                self.logger.send_multipart(['DEBUG', "Agent worker sending PCAP to console"])
                                publisher.send_json({
                                    "payload": packets,
                                    "console": msg['console'],
                                    "request_id": msg['request_id'],
                                    "_function": "PCAP"
                                })
                            else:
                                self.logger.send_multipart(['DEBUG', "Agent worker sending no PCAP to console"])
                                publisher.send_json({
                                    "payload": "No Packets Found",
                                    "console": msg['console'],
                                    "request_id": msg['request_id'],
                                    "_function": "PCAP"
                                })
                                break
                            if workpub.poll(3000):
                                msg = workpub.recv_json()
                                if msg['_function'] == 'AESKEY':
                                    self.AESKEY = msg['key'].decode('base64')
                                elif  msg['_function'] == 'PCAP_ACK':
                                    if msg['status'] == 'success':
                                        break
                                    else:
                                        continue
                            else:
                                attempts += 1
                                if attempts >= 2:
                                    self.logger.send_multipart(['DEBUG', "Agent worker PCAP send failed 3 times, giving up"])
                                    break
                    elif msg['_function'] == 'events':
                        self.logger.send_multipart(['DEBUG', "Agent worker Sending Ack to event sender"])
                        publisher.send_json({
                            "_function": "events",
                            "status": msg['status']
                        })
                    elif msg['_function'] == 'PCAP_ACK':
                        self.logger.send_multipart(['DEBUG', "Agent worker Sending Ack to event sender"])
                        publisher.send_json({
                            "_function": "PCAP_ACK",
                            "status": msg['status']
                        })
                    elif msg['_function'] == 'auth':
                        self.logger.send_multipart(['DEBUG', "Agent worker Sending Auth to event sender"])
                        publisher.send_json(msg)

                if workpub in sockets:
                    msg = workpub.recv_json()
                    if msg['_function'] == 'AESKEY':
                        self.AESKEY = msg['key'].decode('base64')

        except Exception as e:
            #print('{}: {}'.format(e.__class__.__name__,e))
            self.logger.send_multipart(['DEBUG', "Agent worker shutting down"])
            self.logger.close(linger=1000)
            publisher.close(linger=1000)
            work.close(linger=1000)
            sys.exit()

class PCAPprocessor(object):
    def __init__(self, config):
        self.config = config
        self.carver = PCAPCarver(config)

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
