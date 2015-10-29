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

class carvePcap(object):
    def __init__(self, config):
        self.config = config['pcap']

    def ip_to_str(self, address):
        return socket.inet_ntop(socket.AF_INET, address)

    def determine_proto(self, proto, ip):
        try:
            pr = int(proto)
            if proto == 1:
                if ip.p == dpkt.ip.IP_PROTO_ICMP:
                    return True
                else:
                    return False
            elif proto == 6:
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    return True
                else:
                    return False
            elif proto == 17:
                if ip.p == dpkt.ip.IP_PROTO_UDP:
                    return True
                else:
                    return False
            else:
                raise("Protocol %s not supported" % str(proto))
        except:
            try:
                pr = str(proto).upper()
                if pr == 'ICMP':
                    if ip.p == dpkt.ip.IP_PROTO_ICMP:
                        return True
                    else:
                        return False
                elif pr == 'TCP':
                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        return True
                    else:
                        return False
                elif pr == 'UDP':
                    if ip.p == dpkt.ip.IP_PROTO_UDP:
                        return True
                    else:
                        return False
                else:
                    raise("Protocol %s not supported" % str(proto))
            except:
                raise("Protocol %s not supported" % str(proto))

    def carve_pcap_file(self, options, count, thres_time, pcap_file, out_file, out_pcap):
        protocols = {
            'TCP': dpkt.ip.IP_PROTO_TCP,
            6: dpkt.ip.IP_PROTO_TCP,
            'UDP': dpkt.ip.IP_PROTO_UDP,
            17: dpkt.ip.IP_PROTO_UDP,
            'ICMP': dpkt.ip.IP_PROTO_ICMP,
            1: dpkt.ip.IP_PROTO_ICMP,
        }
        proto = options['proto']
        if not proto in protocols.keys():
            raise("Protocol %s not supported" % str(proto))
        src_ip = socket.inet_pton(socket.AF_INET, options['src_ip'])
        src_port = int(options['src_port'])
        dest_ip = socket.inet_pton(socket.AF_INET, options['dest_ip'])
        dest_port = int(options['dest_port'])
        event_time = int(options['event_time'])
        max_packets = int(self.config['max_packets'])
        max_size = int(self.config['max_size']) * 1024 * 1024
        ips = [src_ip,dest_ip]
        for ts, pkt in dpkt.pcap.Reader(open(pcap_file,'r')):
            if ts < int(event_time):
                continue
            if ts > int(thres_time):
                return 'END', count
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            ip = eth.data
            #if not self.determine_proto(proto, ip):
            if not ip.p == protocols[proto]:
                continue
            #sip = self.ip_to_str(ip.src)
            sip = ip.src
            #if not sip == src_ip and not sip == dest_ip:
                #continue
            if not sip in ips:
                continue
            #dip = self.ip_to_str(ip.dst)
            dip = ip.dst
            if not dip in ips:
                continue
            #if not dip == dest_ip and not dip == src_ip:
                #continue
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
                return 'END', count
            if int(out_file.tell()) >= max_size:
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
        stim = time.time()
        for pcap_file in pcap_files:
            get_packets, count = self.carve_pcap_file(options, count, thres_time, pcap_file, out_file, out_pcap)
            if get_packets == 'CONTINUE':
                continue
            else:
                break
        print('Request took %i seconds' % int(int(time.time())-int(stim)))
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
        thres_time = end_time
        pcap_files = self.find_pcap_files(options, thres_time)
        #tmp_name = os.path.join(self.config['temp_directory'], ('%s_%s.pcap' % (str(time.time()), str(options.event_time))))
        out_file = NamedTemporaryFile(mode='w+b', dir=self.config['temp_directory'])
        #out_file = open(tmp_name,'w')
        out_pcap = dpkt.pcap.Writer(out_file)
        count = 0
        for pcap_file in pcap_files:
            print('working on %s' % pcap_file)
            get_packets, count = self.carve_pcap_file(options, count, thres_time, pcap_file, out_file, out_pcap)
            if get_packets == 'CONTINUE':
                continue
            else:
                break
        if count == 0 :
            out_pcap.close()
            out_file.close()
            #os.remove(tmp_name)
            return 'No Packets Found'
        else:
            return out_file

