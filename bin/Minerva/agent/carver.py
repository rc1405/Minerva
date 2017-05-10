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
import os
import sys
import socket
from tempfile import NamedTemporaryFile

import dpkt
import pcap

class PCAPCarver(object):
    def __init__(self, config):
        self.config = config['pcap']

    def carve_pcap_file(self, options, count, thres_time, pcap_file, out_file, out_pcap):
        protocols = {
            'TCP': 'tcp and (host {} and port {}) and (host {} and port {})'.format(
                options['src_ip'], 
                options['src_port'], 
                options['dest_ip'], 
                options['dest_port']
            ),
            6: 'tcp and (host {} and port {}) and (host {} and port {})'.format(
                options['src_ip'], 
                options['src_port'], 
                options['dest_ip'], 
                options['dest_port']
            ),
            'UDP': 'udp and (host {} and port {}) and (host {} and port {})'.format(
                options['src_ip'], 
                options['src_port'], 
                options['dest_ip'], 
                options['dest_port']
            ),
            17: 'udp and (host {} and port {}) and (host {} and port {})'.format(
                options['src_ip'], 
                options['src_port'], 
                options['dest_ip'], 
                options['dest_port']
            ),
            'ICMP': 'icmp and host {} and host {}'.format(options['src_ip'], options['dest_ip']),
            1: 'icmpP and host {} and host {}'.format(options['src_ip'], options['dest_ip']),
        }
        if not options['proto'] in protocols.keys():
            raise("Protocol {} not supported".format(options['proto']))
        event_time = int(options['event_time'])
        max_packets = int(self.config['max_packets'])
        max_size = int(self.config['max_size']) * 1024 * 1024
        write_pcap = out_pcap.writepkt
        pcap_size = out_file.tell
        open_pcap_file = pcap.pcap(pcap_file)
        open_pcap_file.setfilter(protocols[options['proto']])
        for ts, pkt in open_pcap_file:
            if ts < int(event_time) - 300:
                continue
            if ts > int(thres_time):
                return 'END', count
            write_pcap(pkt, ts=ts)
            count = count + 1
            if count == max_packets:
                return 'END', count
            if int(pcap_size()) >= max_size:
                return 'END', count
        return 'CONTINUE', count

    def find_pcap_files(self, options, thres_time):
        matches = []
        files = {}
        keys = []
        last_file = ''
        for root, dirnames, filenames in os.walk(self.config['pcap_directory']):
            for fname in filenames:
                key = int(fname.strip(self.config['prefix']).strip(self.config['suffix']))
                files[key] = os.path.join(root, fname)
                keys.append(key)
        last_file = ''
        count = 0
        keys.sort()
        for f in keys:
            if f < int(options['event_time']):
                last_file = files[f]
                continue
            if len(matches) == 0 and len(last_file) > 0:
                matches.append(last_file)
                count = 1
            matches.append(files[f])
            count = count + 1
            if count >= int(self.config['max_files']):
                return matches
        if len(last_file) > 0:
            if len(matches) == 0:
                matches.append(last_file)
        return matches

    def parse_alert(self, src_ip=None, src_port=None, dest_ip=None, dest_port=None, proto=None, event_time=None):
        if not src_ip or not src_port or not dest_ip or not dest_port or not proto or not event_time:
             raise "Missing Value"
        options = {}
        options['src_ip'] = src_ip
        options['src_port'] = int(src_port)
        options['dest_ip'] = dest_ip
        options['dest_port'] = int(dest_port)
        options['proto'] = proto
        options['event_time'] = event_time
        thres_time = int(options['event_time']) + int(self.config['thres_time'])
        pcap_files = self.find_pcap_files(options, thres_time)
        out_file = NamedTemporaryFile(mode='w+b', dir=self.config['temp_directory'])
        out_pcap = dpkt.pcap.Writer(out_file)
        count = 0
        for pcap_file in pcap_files:
            get_packets, count = self.carve_pcap_file(options, count, thres_time, pcap_file, out_file, out_pcap)
            if get_packets == 'CONTINUE':
                continue
            else:
                break
        if count == 0:
            out_pcap.close()
            out_file.close()
            return 'No Packets Found'
        return out_file

    def parse_flow(self, src_ip=None, src_port=None, dest_ip=None, dest_port=None, proto=None, start_time=None, end_time=None):
        if not src_ip or not src_port or not dest_ip or not dest_port or not proto or not start_time or not end_time:
             raise "Missing Value"
        options = {}
        options['src_ip'] = src_ip
        options['src_port'] = src_port
        options['dest_ip'] = dest_ip
        options['dest_port'] = dest_port
        options['proto'] = proto
        options['event_time'] = start_time
        thres_time = int(end_time)+1
        pcap_files = self.find_pcap_files(options, thres_time)
        out_file = NamedTemporaryFile(mode='w+b', dir=self.config['temp_directory'])
        out_pcap = dpkt.pcap.Writer(out_file)
        count = 0
        for pcap_file in pcap_files:
            get_packets, count = self.carve_pcap_file(options, count, thres_time, pcap_file, out_file, out_pcap)
            if get_packets == 'CONTINUE':
                continue
            else:
                break
        if count == 0 :
            out_pcap.close()
            out_file.close()
            return 'No Packets Found'
        else:
            return out_file

