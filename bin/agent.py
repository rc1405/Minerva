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
import os
from Minerva import core, agent
from multiprocessing import Process, Lock, active_children
import time
import sys
import ssl
import platform
import json
import subprocess
import pprint

def tailFile(cur_config, fname, send_lock):
    sensor_name = cur_config['sensor_name']
    ftype = cur_config['logfiles'][fname]['type']
    pfile = cur_config['logfiles'][fname]['position_file']
    ftailer = agent.log_tailer.TailLog(fname, pfile)
    converter = agent.parsers.get_parser(ftype, sensor_name)
    count = 1
    batchsize = int(cur_config['Minerva_Server']['send_batch'])
    sendwait = int(cur_config['Minerva_Server']['send_wait'])
    batch = []
    start_wait = time.time()
    try:
        for event in ftailer.tail():
            batch.append(converter.convert(event))
            count += 1
            tdiff = time.time() - start_wait
            if tdiff > sendwait or count > batchsize:
                send_lock.acquire()
                retval = 'reject'
                while True:
                    rval = send(cur_config, batch)
                    if rval == 'accept':
                        retval == 'accept'
                        break
                    time.sleep(300)
                send_lock.release()
                batch = []
                count = 1
                start_wait = time.time()
    except:
        ftailer.write_pos()
        sys.exit()
def send(cur_config, batch):
    keyfile = cur_config['client_private']
    certfile = cur_config['Minerva_Server']['server_cert']
    s = socket(AF_INET, SOCK_STREAM)
    if not os.path.exists(certfile):
        server_cert = ssl.get_server_certificate((cur_config['Minerva_Server']['destination'], int(cur_config['Minerva_Server']['port'])))
        scert = open(cur_config['Minerva_Server']['server_cert'],'w')
        scert.writelines(server_cert)
        scert.flush()
        scert.close()
    cert = open(cur_config['client_cert'],'r').read()
    s_ssl = ssl.wrap_socket(s, ca_certs=cur_config['Minerva_Server']['server_cert'], cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_SSLv3)
    s_ssl.connect((cur_config['Minerva_Server']['destination'], int(cur_config['Minerva_Server']['port'])))
    if len(batch) == 0:
        s_ssl.send('GET_CERT')
    else:
        s_ssl.send('SERVER_AUTH')
    s_ssl.send(cert)
    stat = s_ssl.read()
    if stat == 'reject':
        s_ssl.close()
        return stat
    if len(batch) > 0:
        for b in batch:
            s_ssl.send(json.dumps(b))
            s_ssl.send('END_EVENT')
        s_ssl.send(b'END')
        server_resp = s_ssl.recv(8192)
        s_ssl.close()
        return server_resp
    s_ssl.close()
    return
def genKey(cur_config):
    if not os.path.exists(os.path.dirname(cur_config['client_cert'])):
        os.mkdir(os.path.dirname(cur_config['client_cert']))
    if not os.path.exists(os.path.dirname(cur_config['client_private'])):
        os.mkdir(os.path.dirname(cur_config['client_private']))
    cmd = [ 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', cur_config['client_private'], '-out', cur_config['client_cert'], '-days', '3650', '-nodes', '-batch']
    subprocess.call(cmd)

def main():
    cur_config = core.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')).conf['Agent_forwarder']
    if not os.path.exists(cur_config['client_cert']) or not os.path.exists(cur_config['client_private']):
        genKey(cur_config)
    active_processes = []
    send_lock = Lock()
    try:
        for l in cur_config['logfiles'].keys():
    	    pr = Process(name=l, target=tailFile, args=((cur_config, l, send_lock)))
            pr.start()
            active_processes.append(pr)
        while True:
            for l in active_processes:
                if not l in active_children():
                    active_processes.remove(l)
                    pr = Process(name=l.name, target=tailFile, args=((cur_config, l.name, send_lock)))
                    pr.start()
                    active_processes.append(pr)
            time.sleep(10)
    except:
        time.sleep(1)
        for l in active_processes:
            l.terminate()
        sys.exit()
main()
