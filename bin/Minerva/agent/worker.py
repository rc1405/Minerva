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
        self.logger = minerva_core.get_socket(channels)
        self.AESKEY = False
        self.SRVKEY = False

    def _decrypt_aes(self, payload):
        try:
            cipher = M2Crypto.EVP.Cipher('aes_256_cbc', key=self.AESKEY, iv=self.AESKEY, op=0)
            events = json.loads(cipher.update(payload.decode('base64')) + cipher.final())
            self.logger.send_multipart(['DEBUG', "Agent worker decrypted AES message"])
            return events
        except:
            self.logger.send_multipart(['ERROR', "Agent worker unable to decrypt AES message"])
            return False

    def start(self):
        context = zmq.Context.instance()

        work = context.socket(zmq.PULL)
        work.connect(self.channels['worker'])
        self.logger.send_multipart(['DEBUG', "Agent worker listening for events"])

        publisher = context.socket(zmq.REQ)
        publisher.connect(self.channels['pub'])
        self.logger.send_multipart(['DEBUG', "Agent worker connected to publisher"])

        pcapWorker = PCAPprocessor(self.config)

        publisher.send_json({"_function": "AESKEY"})
        msg = publisher.recv_json()
        self.AESKEY = msg['key'].decode('base64')
        self.logger.send_multipart(['DEBUG', "Agent worker received AES key"])


        try:
            while True:
                sensor, msg = work.recv_multipart()
                msg = json.loads(msg)
                self.logger.send_multipart(['DEBUG', "Agent worker received work task"])
                if '_payload' in msg.keys():
                    msg = self._decrypt_aes(msg['_payload'])
                    if not msg:
                        publisher.send_json({"payload": "reauth"})
                        self.logger.send_multipart(['DEBUG', "Agent worker requesting new AES key"])
                        continue
    
                if msg['_function'] == 'PCAP':
                    #print('pcap')
                    self.logger.send_multipart(['DEBUG', "Agent worker received PCAP Request"])
                    packets = pcapWorker.process(msg['request'])
                    attempts = 0
                    while True:
                        if packets:
                            #print('packets')
                            self.logger.send_multipart(['DEBUG', "Agent worker sending PCAP to console"])
                            publisher.send_json({
                                "payload": packets,
                                "console": msg['console'],
                                "request_id": msg['request_id'],
                                "_function": "PCAP"
                            })
                        else:
                            #print('no packets')
                            self.logger.send_multipart(['DEBUG', "Agent worker sending no PCAP to console"])
                            publisher.send_json({
                                "payload": "No Packets Found",
                                "console": msg['console'],
                                "request_id": msg['request_id'],
                                "_function": "PCAP"
                            })
                        status = publisher.recv_json()
                        if status['status'] == 'success':
                            break
                        elif attempts >= 2:
                            self.logger.send_multipart(['DEBUG', "Agent worker PCAP send failed 3 times, giving up"])
                            break
                        elif status['status'] == 'failure':
                            self.logger.send_multipart(['DEBUG', "Agent worker PCAP send failed, retrying"])
                            attempts += 1
                            self.AESKEY = status['KEY'].decode('base64')
        except:
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
