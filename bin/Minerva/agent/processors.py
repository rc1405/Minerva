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

class PCAPprocessor(object):
    def __init__(self, config, carver):
        self.config = config
        self.server_cert = config['target_addr']['server_cert']
        self.client_cert = config['client_cert']
        self.client_key = config['client_private']
        self.carver = carver

    def process(self, host, s):
        print('starting processing')
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
        if options['request_type'] == 'alert':
            tmp_file = self.carver.parse_alert(src_ip=options['src_ip'], src_port=options['src_port'], dest_ip=options['dest_ip'], dest_port=options['dest_port'], proto=options['proto'], event_time=options['event_time'])
        elif options['request_type'] == 'flow':
            tmp_file = self.carver.parse_flow(src_ip=options['src_ip'], src_port=options['src_port'], dest_ip=options['dest_ip'], dest_port=options['dest_port'], proto=options['proto'], start_time=options['start_time'], end_time=options['end_time'])
            
        if tmp_file == 'No Packets Found':
            s.send('No Packets Found')
            s.send('END_EVENT')
            s.close()
            return

        tmp_file.seek(0)
        pcap = tmp_file.read(8192)
        while (pcap):
            s.send(pcap)
            pcap = tmp_file.read(8192)
        s.send(b'END_EVENT')
        s.close()
        return
        
    def decrypt_options(self, encrypted_options):
        server_cert = M2Crypto.X509.load_cert(str(self.server_cert))
        pub_key = server_cert.get_pubkey()
        rsa_key = pub_key.get_rsa()
        try:
            decrypted_options = json.loads(rsa_key.public_decrypt(encrypted_options, M2Crypto.RSA.pkcs1_padding))
        except:
            raise 'Invalid request'
        return decrypted_options

