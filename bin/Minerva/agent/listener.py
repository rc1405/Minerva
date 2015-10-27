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


from socket import socket, AF_INET, SOCK_STREAM
from multiprocessing import Process, active_children
import time
import ssl

class RequestListener(object):
    def __init__(self, config):
        self.config = config
        self.max_threads = config['listener']['threads']
        self.ip = config['listener']['ip']
        self.port = int(config['listener']['port'])

    def listener(self, recv_data):
        print('starting receiver')
        KEYFILE = self.config['client_private']
        CERTFILE = self.config['client_cert']
        s = socket(AF_INET, SOCK_STREAM)
        s.bind((self.ip, self.port))
        s.listen(1)
        s_ssl = ssl.wrap_socket(s, keyfile=KEYFILE, certfile=CERTFILE, server_side=True, ssl_version=ssl.PROTOCOL_SSLv3)
        active_recv = []
        while True:
            try:
                for p in active_recv:
                    if p not in active_children():
                        p.join()
                        active_recv.remove(p)
                if len(active_children()) < int(self.max_threads):
                    print('accepting connections')
                    c, a = s_ssl.accept()
                    print('Got connection', c, a)
                    pr = Process(target=recv_data, args=((a[0], c)))
                    pr.start()
                    active_recv.append(pr)
                else:
                    print('sleeping')
                    time.sleep(.001)
            except Exception as e:
                print('{}: {}'.format(e.__class__.__name__,e))