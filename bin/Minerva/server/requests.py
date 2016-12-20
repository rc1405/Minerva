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

import bson
import time
import json
import uuid
from tempfile import SpooledTemporaryFile, NamedTemporaryFile

import M2Crypto
import pymongo
import zmq
import platform

class HandleRequests(object):

    def __init__(self, minerva_core):
        db = minerva_core.get_db()
        self.conf = minerva_core.conf
        self.flow = db.flow
        self.certs = db.certs
        self.alerts = db.alerts
        self.sensors = db.sensors
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']
        keys = db.certs.find_one({"type": "webserver"})
        key = keys['key']
        self.PUBCERT = keys['CERT']
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(key))
        self.SRVKEY = False
        self.AESKEY = False
        self.name = 'webserver'

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


    def _decrypt_aes(self, payload):
        try:
            cipher = M2Crypto.EVP.Cipher('aes_256_cbc', key=self.AESKEY, iv=self.AESKEY, op=0)
            events = json.loads(cipher.update(payload.decode('base64')) + cipher.final())
            return events
        except:
            return False

    def _encrypt_rsa(self, cert, payload):
        #CERT = M2Crypto.X509.load_cert_string(str(cert))
        PUBKEY = cert.get_pubkey()
        RSA = PUBKEY.get_rsa()
        try:
            enc_payload = RSA.public_encrypt(payload, M2Crypto.RSA.pkcs1_padding).encode('base64')
            return enc_payload
        except:
            return False

    def send_request(self, request):
        req_id = str(uuid.uuid4()) # Create random 128-bit UUID
        context = zmq.Context() # zmq socket
        sender = context.socket(zmq.PUSH) # socket type - DEALER
        sender.identity = "%s|-_%s" % (self.name, req_id) # sender ID 'webserver-_UUID'
        receiver = context.socket(zmq.SUB) # socket type - SUB 

        receiver.identity = self.name # webserver
        receiver.setsockopt(zmq.SUBSCRIBE, "%s|-_%s" % (self.name, req_id)) # setsockopt - Default socket options for new sockets created by this context
# socket type = SUBSCRIBE
# Establishes a new message filter on 'receiver' SUB socket that will only subscribe to (self.name, req_id)
        receivers = {}

        '''GREEN LINE'''
        results = self.certs.find_one({"type": "receiver"})
        if not results:
            return 'error'
        for r in results['receivers']:
            receivers[r] = context.socket(zmq.PUSH)
            receivers[r].identity = "%s|-_%s" % (self.name, str(r))
            ip, recv_port, sub_port = r.split('-')
            sender.connect('tcp://%s:%s' % (ip, recv_port))
            receivers[r].connect('tcp://%s:%s' % (ip, recv_port))
            receiver.connect('tcp://%s:%s' % (ip, sub_port))


        sender.send_json({
            "_function": "auth",
            "_cert": self.PUBCERT
        })

        msg = receiver.recv_json()
        server_cert = M2Crypto.X509.load_cert_string(str(msg['_cert']))
        pub_key = server_cert.get_pubkey()
        rsa_key = pub_key.get_rsa()
        self.SRVKEY = rsa_key
        AESKEY = self._decrypt_rsa(msg['_message'])
        if AESKEY:
            self.AESKEY = AESKEY.decode('base64')
        else:
            return "Bad Key Exchange"

        for k in receivers.keys():
            receivers[k].send_json({
                "mid": self.name,
                "_payload": self._encrypt_aes(json.dumps({
                    "_function": "PCAP",
                    "_action": "request",
                    #"console": self.name,
                    "console": "%s|-_%s" % (self.name, req_id),
                    "request_id": req_id,
                    "request": request,
                    "target": request['sensor']
                })),
                "_cert": self.PUBCERT
            })
        '''END OF GREEN LINE'''

        start_time = int(time.time())
        threshold = int(self.conf['Webserver']['web']['pcap_timeout'])

        msg = False
        while int(time.time()) - start_time < threshold:
            '''BLUE LINE'''
            if receiver.poll(1000):
                mid, msg = receiver.recv_multipart()
                msg = json.loads(msg)
                break
            '''END OF BLUE LINE'''

        if msg:
            denc_msg = self._decrypt_aes(msg['_payload'])
            if not denc_msg:
                sender.send_json({
                    "_function": "auth",
                    "_cert": self.PUBCERT
                })

                msg = sender.recv_json()
                AESKEY = self._decrypt_rsa(msg['_message'])
                if AESKEY:
                    self.AESKEY = AESKEY.decode('base64')
                    denc_msg = self._decrypt_aes(msg['_payload'])
                    if not denc_msg:
                        return "Error Decoding Msg"
                else:
                    return "Unable to decode msg"
            if denc_msg['payload'] == 'No Packets Found':
                return 'No Packets Found'
            tmp_file = SpooledTemporaryFile(mode='wb')
            tmp_file.write(denc_msg['payload'].decode('base64'))
            tmp_file.seek(0)

            return tmp_file
        else:
            return "No Response from sensor"

    def alertPCAP(self, events):
        #TODO Add loop around events
        orig_alert = self.alerts.find_one({ "_id": bson.objectid.ObjectId(events[0]) })

        options = {}
        options['src_ip'] = orig_alert['src_ip']
        options['src_port'] = orig_alert['src_port']
        options['dest_ip'] =orig_alert['dest_ip']
        options['dest_port'] = orig_alert['dest_port']
        options['proto'] = orig_alert['proto']
        options['event_time'] = orig_alert['timestamp'].strftime('%s')
        options['sid'] = orig_alert['alert']['signature_id']
        options['rev'] = orig_alert['alert']['rev']
        options['gid'] = orig_alert['alert']['gid']
        options['sensor'] = orig_alert['sensor']
        options['request_type'] = 'alert'

        pcap = self.send_request(options)

        return pcap

    def flowPCAP(self, events):
        #TODO Add loop around events
        results = self.flow.find_one({ "_id": bson.objectid.ObjectId(events[0]) })

        options = {}
        options['src_ip'] = orig_alert['src_ip']
        options['src_port'] = orig_alert['src_port']
        options['dest_port'] = orig_alert['dest_port']
        options['proto'] = orig_alert['proto']
        options['start_time'] = orig_alert['netflow']['start'].strftime('%s')
        options['end_time'] = orig_alert['netflow']['end'].strftime('%s')
        options['sensor'] = orig_alert['sensor']
        options['request_type'] = 'flow'

        pcap = self.send_request(options)

        return pcap
