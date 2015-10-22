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
from optparser import OptionParser

import dpkt

class carvePcap(object):
    def __init__(self, config):
        self.config = config

    def epoch_to_utc(self, epoch):
        return int(time.mktime(time.gmtime(float(epoch))))

    def carve_pcap_file(self, options, thres_time, pcap_file, out_file, out_pcap):
        proto = determine_proto(options.proto)
        src_ip = options.src_ip
        src_port = int(options.src_port)
        dest_ip = options.dest_ip
        dest_port = int(options.dest_port)
        event_time = int(options.event_time)
        count = 0
        max_packets = int(self.config['max_packets'])
        max_size = int(self.config['max_size']) * 1024 * 1024
        for ts, pkt in dpkt.pcap.Reader(open(pcap_file,'r')):
            ts = epoch_to_utc(ts)
            if ts < event_time:
                continue
            if ts > thres_time:
                return False
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            ip = eth.data
            if ip.p != proto:
                continue
            sip = ip_to_str(ip.src)
            if not sip == src_ip and not sip == dest_ip:
                continue
            dip = ip_to_str(ip.dst)
            if not dip == dest_ip and not dip == src_ip:
                continue
            data = ip.data
            spt = int(data.sport)
            dpt = int(data.dport)
            if not (sip == src_ip and spt == src_port) and not (sip == dest_ip and spt == dest_port):
                continue
            if not (dip == src_ip and dpt == src_port) and not (dip == dest_ip and dpt == dest_port):
                continue
            out_pcap.writepkt(pkt, ts=ts)
            count = count + 1
            if count == max_packets:
                return False
            if int(out_file.tell()) >= max_size:
                return False
        return True
    def find_pcap_files(self, options, thres_time):
        matches = []
        last_file = ''
        for root, dirnames, filenames in os.walk(self.config['pcap_directory']):
            filenames.sort()
            for fname in filenames:
                last_file = os.path.join(root, fname)
                if epoch_to_utc(fname.strip(self.config['prefix']).strip(self.config['suffix'])) < int(options.event_time):
                    continue
                if len(matches) == 0:
                    matches.append(last_file)
                    count = 1
                matches.append(os.path.join(root, fname))
                count = count + 1
                if count >= int(self.config['max_files']):
                    return matches
            if len(last_file) > 0:
                if len(matches) == 0:
                    matches.append(last_file)
        return matches
    def parse_alert(self, options):
        #config = {}
        #config['max_packets'] = 100
        #config['max_size'] = 10
        #config['max_files'] = 5
        #config['thres_time'] = 300
        #config['prefix'] = ''
        #config['suffix'] = '.pcap'
        #config['pcap_directory'] = '/opt/pcap'
        #config['temp_directory'] = '/tmp'
        options = get_args()
        thres_time = int(options.event_time) + int(self.config['thres_time'])
        pcap_files = find_pcap_files(options, thres_time)
        tmp_name = os.path.join(self.config['temp_directory'], ('%s_%s.pcap' % (str(time.time()), str(options.event_time))))
        out_file = open(tmp_name,'w')
        out_pcap = dpkt.pcap.Writer(out_file)
        for pcap_file in pcap_files:
            get_packets = carve_pcap_file(options, thres_time, pcap_file, out_file, out_pcap)
            if get_packets:
                continue
            else:
                break
        return tmp_name
    def parse_flow(self, options):
        #config = {}
        #config['max_packets'] = 100
        #config['max_size'] = 10
        #config['max_files'] = 5
        #config['thres_time'] = 300
        #config['prefix'] = ''
        #config['suffix'] = '.pcap'
        #config['pcap_directory'] = '/opt/pcap'
        #config['temp_directory'] = '/tmp'
        options = get_args()
        thres_time = int(options.event_time) + int(self.config['thres_time'])
        pcap_files = find_pcap_files(options, thres_time)
        tmp_name = os.path.join(self.config['temp_directory'], ('%s_%s.pcap' % (str(time.time()), str(options.event_time))))
        out_file = open(tmp_name,'w')
        out_pcap = dpkt.pcap.Writer(out_file)
        for pcap_file in pcap_files:
            get_packets = carve_pcap_file(options, thres_time, pcap_file, out_file, out_pcap)
            if get_packets:
                continue
            else:
                break
        return tmp_name

