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
import ssl
import json
import uuid
from multiprocessing import Process, active_children, Queue
from tempfile import SpooledTemporaryFile, NamedTemporaryFile
from socket import socket, AF_INET, SOCK_STREAM, error

import M2Crypto
import pymongo

class AlertProcessor(object):
    def __init__(self, minerva_core, log_queue):
        self.config = minerva_core.conf
        self.core = minerva_core
        #client = pymongo.MongoClient(config['Webserver']['db']['url'],int(config['Webserver']['db']['port']))
        #self.collection = client.minerva.sensors
        self.log_queue = log_queue
    def process(self, host, s):
        header = s.read()
        if header == 'GET_CERT':
            s.send('accept')
            s.close()
            return
        elif header != 'SERVER_AUTH':
            #print('bad header: %s' % header)
            s.send('reject')
            s.close()
            return
        cert = s.recv(8192)
        m2cert = M2Crypto.X509.load_cert_string(cert)
        if m2cert.verify(m2cert.get_pubkey()):
            CN = m2cert.get_issuer().get_entries_by_nid(13)[0].get_data().as_text()
        else:
            #print('bad cert')
            s.send('reject')
            s.close()
            return
        db = self.core.get_db()
        collection = db.sensors
        results = collection.find({ "SERVER": CN })
        result = []
        for r in results:
            result.append(r)
        #print('finished building results')
        if len(result) == 0:
            #print('sensor not approved, inserting')
            s.send('GET_PORT')
            recv_port = s.recv()
            try:
                recv_p = int(recv_port)
            except ValueError:
                s.send('reject')
                s.close()
                return
            collection.insert({ "time_created": time.time(), "last_modified": time.time(), "SERVER": CN, "cert": cert, "IP": host, "STATUS": "NOT_APPROVED", "sensor_port": int(recv_port), "receiver": self.config['Event_Receiver']['PCAP']['ip'], "receiver_port": int(self.config['Event_Receiver']['PCAP']['port']) })
            s.send('reject')
            s.close()
            return
        elif len(result) > 1:
            #print('More than one entry exists %s, %s' % (CN, host))
            s.send('reject')
            s.close()
            return
        elif result[0]['receiver'] != self.config['Event_Receiver']['PCAP']['ip']:
            collection.update({ "SERVER": CN }, { "$set": { "STATUS": "RECEIVER_CHANGED"}})
            s.send('reject')
            s.close()
            return
        elif result[0]['IP'] != host and result[0]['STATUS'] == '_DENIED':
            collection.update({ "SERVER": CN }, { "$set": { "IP": host, "receiver": self.config['Event_Receiver']['PCAP']['ip'], "cert": cert, "STATUS": "IP_CHANGED", "last_modified": time.time() }})
            s.send('reject')
            s.close()
        elif result[0]['cert'] != cert:
            #print('cert changed')
            collection.update({ "SERVER": CN }, { "$set": { "cert": cert, "STATUS": "CERT_CHANGED", "last_modified": time.time() }})
            s.send('reject')
            s.close()
            return
        elif result[0]['STATUS'] != "APPROVED":
            #print('sensor not approved')
            s.send('reject')
            s.close()
            return
        else:
            public_key = m2cert.get_pubkey()
            rsa_key = public_key.get_rsa()
            challenge = ('%s-%s' % ( uuid.uuid4().hex, str(time.time())))
            encrypted_challenge = rsa_key.public_encrypt(challenge, M2Crypto.RSA.pkcs1_padding)
            s.send(encrypted_challenge)
            challenge_response = s.recv(8192)
            if str(challenge) != str(challenge_response):
                #print('Challenge Response Failed')
                s.send('reject')
                s.close()
                return
            s.send('accept')

        json_data = ''
        while True:
            data = s.recv(8192)
            if data == b'END_EVENT':
                self.log_queue.put(json_data)
                json_data = ''
            elif data == b'END':
                break
            else:
                json_data = json_data + data
        s.send('accept')
        s.close()
class PCAPprocessor(object):
    def __init__(self, minerva_core):
        self.config = minerva_core.conf
        self.core = minerva_core
        #client = pymongo.MongoClient(config['Webserver']['db']['url'],int(config['Webserver']['db']['port']))
        #cert = client.minerva.certs
        #self.web_cert = cert.find_one({"type": "webserver"})['cert']
        #self.sensors = client.minerva.sensors

    def process(self, host, s):
        #print('starting processing')
        encrypted_options = ''
        while True:
            data = s.recv(8192)
            if data == b'END_EVENT':
                break
            else:
                encrypted_options = encrypted_options + data
        try:
            options = self.decrypt_options(encrypted_options)
        except:
            s.close()
            return
        #print('requesting pcap from sensor %s' % options['sensor'])
        soc = socket(AF_INET, SOCK_STREAM)
        soc.setblocking(0)
        soc.settimeout(int(self.config['Event_Receiver']['PCAP']['timeout']))
        db = self.core.get_db()
        sensors = db.sensors
        client_info = sensors.find_one( { "SERVER": options['sensor'] })
        client_cert = client_info['cert']
        cert_tmp = NamedTemporaryFile(mode='w+b', suffix='.pem')
        cert_tmp.write(client_cert)
        cert_tmp.flush()
        #soc_ssl = ssl.wrap_socket(soc, ca_certs=client_cert, cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_SSLv3)
        soc_ssl = ssl.wrap_socket(soc, ca_certs=cert_tmp.name, cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_SSLv3)
        encrypted_options = self.encrypt_requests(self.config, options)
        try:
            soc_ssl.connect((client_info['IP'], int(client_info['sensor_port'])))
        except error:
            s.send('Sensor cannot be reached')
            s.close()
            return 
        soc_ssl.send(encrypted_options)
        soc_ssl.send('END_EVENT')
        tmp_file = SpooledTemporaryFile(mode='wb')
        while True:
            try:
                data = soc_ssl.recv(8192)
            except ssl.SSLError:
                #print('Timed Out')
                s.send('Request Timed Out')
                s.close()
                return
            if data == b'END_EVENT':
                break
            elif data != 'No Packets Found':
                tmp_file.write(data)
            else:
                s.send('No Packets Found')
                s.close()
                cert_tmp.close()
                return
        tmp_file.seek(0)
        pcap = tmp_file.read(8192)
        try:
            while (pcap):
                s.send(pcap)
                pcap = tmp_file.read(8192)
            s.send(b'END_EVENT')
        except error:
            s.close()
            return 
        s.close()
        cert_tmp.close()
        return
        
    def encrypt_requests(self, cur_config, request):
        private_key = M2Crypto.RSA.load_key(cur_config['Event_Receiver']['certs']['private_key'])
        encrypted_request = private_key.private_encrypt(json.dumps(request), M2Crypto.RSA.pkcs1_padding)
        return encrypted_request 

    def decrypt_options(self, encrypted_options):
        db = self.core.get_db()
        web_cert = db.certs.find_one({"type": "webserver"})['cert']
        web_cert = M2Crypto.X509.load_cert_string(str(web_cert))
        pub_key = web_cert.get_pubkey()
        rsa_key = pub_key.get_rsa()
        try:
            decrypted_options = json.loads(rsa_key.public_decrypt(encrypted_options, M2Crypto.RSA.pkcs1_padding))
        except:
            raise 'Invalid request'
        return decrypted_options

