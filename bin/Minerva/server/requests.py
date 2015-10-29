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

import pymongo
import bson
import time
import json
from tempfile import SpooledTemporaryFile, NamedTemporaryFile
from socket import AF_INET, SOCK_STREAM, socket
import ssl
import M2Crypto

class HandleRequests(object):
    def __init__(self, minerva_core):
        db = minerva_core.get_db()
        self.conf = minerva_core.conf
        self.flow = db.flow
        self.certs = db.certs
        self.alerts = db.alerts
        self.sensors = db.sensors
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']

    def get_receiver(self, sensor):
        results = list(self.sensors.aggregate([ { "$match": { "SERVER": sensor }},{ "$project": { "ip": "$receiver", "port": "$receiver_port" }}]))[0]
        ip = results['ip']
        port = results['port']
        #ip, port = list(self.sensors.aggregate([ { "$match": { "SERVER": sensor }},{ "$project": { "ip": "$receiver", "port": "$receiver_port" }}]))
        cert = list(self.certs.aggregate([ { "$match": { "type": "receiver", "ip": ip }}, { "$project": { "cert": "$cert" }}]))[0]['cert']
        cert_file = NamedTemporaryFile(mode='w+b', suffix='.pem')
        cert_file.writelines(cert)
        cert_file.flush()
        return ip, port, cert_file

    def encrypt_options(self, request):
        private_key = M2Crypto.RSA.load_key(self.conf['Webserver']['web']['certs']['webserver_key'])
        encrypted_request = private_key.private_encrypt(json.dumps(request), M2Crypto.RSA.pkcs1_padding)
        return encrypted_request

    def send_request(self, ip, port, cert, options):
        s = socket(AF_INET, SOCK_STREAM)
        s_ssl = ssl.wrap_socket(s, ca_certs=cert.name, cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_SSLv3)
        s_ssl.connect((ip, int(port)))
        s_ssl.send(options)
        s_ssl.send('END_EVENT')
        tmp_file = SpooledTemporaryFile(mode='wb')
        while True:
            data = s_ssl.recv(8192)
            if data == b'END_EVENT':
                break
            elif data == 'No Packets Found':
                return 'No Packets Found'
            else:
                tmp_file.write(data)
        tmp_file.seek(0)
        cert.close()
        return tmp_file

    def alertPCAP(self, events, grab_all=False):
        #TODO Add loop around events
        results = self.alerts.aggregate([ { "$match": { "_id": bson.objectid.ObjectId(events[0]) }}, { "$project": { "document": "$$ROOT"}}])
        for orig_alert in results:
            src_ip = orig_alert['document']['src_ip']
            src_port = orig_alert['document']['src_port']
            dest_ip =orig_alert['document']['dest_ip']
            dest_port = orig_alert['document']['dest_port']
            proto = orig_alert['document']['proto']
            epoch = orig_alert['document']['epoch']
            sid = orig_alert['document']['alert']['signature_id']
            rev = orig_alert['document']['alert']['rev']
            gid = orig_alert['document']['alert']['gid']
        if grab_all:
            sensors = list(self.alerts.distinct("sensor", filter={ "src_ip": src_ip, "src_port": src_port, "dest_ip": dest_ip, "dest_port": dest_port, "proto": proto, "epoch": epoch, "alert.signature_id": sid, "alert.rev": rev, "alert.gid": gid}))
        else:
            sensors = [orig_alert['document']['sensor']]
        options = {}
        options['src_ip'] = src_ip
        options['src_port'] = src_port
        options['dest_ip'] = dest_ip
        options['dest_port'] = dest_port
        options['proto'] = proto
        options['event_time'] = epoch
        #convert from list or do it on the receiver
        options['request_type'] = 'alert'
        for sensor in sensors:
            options['sensor'] = sensor
            encrypted_options = self.encrypt_options(options)
            ip, port, cert = self.get_receiver(sensor)
            pcap = self.send_request(ip, port, cert, encrypted_options)
            yield pcap

