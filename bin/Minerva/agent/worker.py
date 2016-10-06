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

import M2Crypto
from .carver import PCAPCarver

class AgentWorker(object):
    def __init__(self, cur_config, channels):
        self.channels = channels
        self.config = cur_config
        self.AESKEY = False
        self.SRVKEY = False

    def _decrypt_aes(self, payload):
        try:
            cipher = M2Crypto.EVP.Cipher('aes_256_cbc', key=self.AESKEY, iv=self.AESKEY, op=0)
            events = json.loads(cipher.update(payload.decode('base64')) + cipher.final())
            return events
        except:
            return False

    def start(self):
        context = zmq.Context.instance()

        work = context.socket(zmq.PULL)
        work.connect(self.channels['worker'])

        publisher = context.socket(zmq.REQ)
        publisher.connect(self.channels['pub'])

        pcapWorker = PCAPprocessor(self.config)

        publisher.send_json({"_function": "AESKEY"})
        msg = publisher.recv_json()
        self.AESKEY = msg['key'].decode('base64')


        while True:
            sensor, msg = work.recv_multipart()
            print(msg)
            msg = json.loads(msg)
            if '_payload' in msg.keys():
                msg = self._decrypt_aes(msg['_payload'])
                if not msg:
                    publisher.send_json({"payload": "reauth"})
                    continue
                print(msg)

            if msg['_function'] == 'PCAP':
                print('pcap')
                packets = pcapWorker.process(msg['request'])
                attempts = 0
                while True:
                    if packets:
                        print('packets')
                        publisher.send_json({
                            "payload": packets,
                            "console": msg['console'],
                            "request_id": msg['request_id'],
                            "_function": "PCAP"
                        })
                    else:
                        print('no packets')
                        publisher.send_json({
                            "payload": "No Packets Found",
                            "console": msg['console'],
                            "request_id": msg['request_id'],
                            "_function": "PCAP"
                        })
                    status = publisher.recv_json()
                    if status['status'] == 'success':
                        print('done')
                        break
                    elif status['status'] == 'failure':
                        print('failed')
                        attempts += 1
                        self.AESKEY = status['KEY'].decode('base64')

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
