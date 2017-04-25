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

import yaml
import os
import ssl
import sys
import threading
import zmq
from logging import DEBUG, INFO, getLogger, Formatter
from logging.handlers import RotatingFileHandler

class MinervaConfigs():
    def __init__(self, **kwargs):
        if not 'conf' in kwargs:
            dir_name = os.path.dirname(os.path.dirname(sys.argv[0]))
            if len(dir_name) == 0:
                conf = os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')
            else:
                conf = os.path.join(os.path.dirname(os.path.dirname(sys.argv[0])),'etc','minerva.yaml')
        else:
            conf = kwargs['conf']
        if not os.path.exists(conf):
            raise "Config File not found"
        with open(conf,'r') as f:
            config = yaml.load(f)
        self.conf = config
    def get_db(self):
        import pymongo
        db_conf = self.conf['Database']['db']

        if int(db_conf['port']) == 0:
            conn_str = db_conf['url']
        else:
            conn_str = "%s:%i" % (db_conf['url'], int(db_conf['port']))

        if db_conf['useAuth']:
            if db_conf['AuthType'] == 'Password':
                if db_conf['useSSL']:
                    client = pymongo.MongoClient(conn_str,
                                             ssl=True,
                                             ssl_cert_reqs=ssl.CERT_REQUIRED,
                                             ssl_ca_certs=ssl_ca_certs)
                else:
                    client = pymongo.MongoClient(conn_str)
                client.minerva.authenticate(db_conf['username'], password=db_conf['password'].decode('base64'), mechanism=db_conf['PW_Mechanism'])
            elif db_conf['AuthType'] == 'X509':
                client = pymongo.MongoClient(conn_str,
                                             ssl=True,
                                             ssl_certfile=db_conf['auth_cert'],
                                             ssl_cert_reqs=ssl.CERT_REQUIRED,
                                             ssl_ca_certs=db_conf['ssl_ca_certs'])
                client.minerva.authenticate(db_conf['x509Subject'], mechanism='MONGODB-X509')
        else:
            client = pymongo.MongoClient(conn_str)
        return client.minerva

    def parse_web_configs(self, new_config):
        config = self.conf
        db = self.get_db()
        config['Database']['db']['url'] = new_config['db_ip']
        config['Database']['db']['port'] = int(new_config['db_port'])
        config['Database']['db']['auth_cert'] = new_config['auth_cert']
        config['Database']['db']['PW_Mechanism'] = new_config['pwmechanism']
        config['Database']['db']['username'] = new_config['db_user']
        config['Database']['db']['useSSL'] = new_config['useSSL']
        config['Database']['db']['ssl_certfile'] = new_config['ssl_cert']
        config['Database']['db']['ssl_ca_certs'] = new_config['ssl_ca']
        config['Database']['db']['x509Subject'] = new_config['db_cert_subj']

        if len(new_config['db_pass']) > 0:
            config['Database']['db']['password'] = new_config['db_pass'].encode('base64')
        config['Database']['db']['AuthType'] = new_config['AuthType']
        if len(new_config['web_motd']) > 0:
            config['Webserver']['web']['motd'] = new_config['web_motd'].encode('base64')
        config['Webserver']['web']['port'] = int(new_config['web_port'])
        config['Webserver']['web']['hostname'] = str(new_config['web_host'])
        config['Webserver']['web']['bindIp'] = new_config['web_ip']
        config['Webserver']['web']['web_threads'] = int(new_config['web_threads'])
        config['Webserver']['web']['pcap_timeout'] = int(new_config['pcap_timeout'])
        config['Webserver']['web']['password_requirements']['password_tries'] = int(new_config['pass_tries'])
        config['Webserver']['web']['password_requirements']['password_max_age'] = int(new_config['pass_age'])
        config['Webserver']['web']['password_requirements']['password_min_length'] = int(new_config['pass_min'])
        config['Webserver']['web']['password_requirements']['digit_count'] = int(new_config['digit_count'])
        config['Webserver']['web']['password_requirements']['lower_count'] = int(new_config['lower_count'])
        config['Webserver']['web']['password_requirements']['upper_count'] = int(new_config['upper_count'])
        config['Webserver']['web']['password_requirements']['special_count'] = int(new_config['special_count'])
        config['Webserver']['web']['certs']['server_cert'] = str(new_config['cert_path'])
        config['Webserver']['web']['certs']['server_key'] = str(new_config['key_path'])
        config['Webserver']['web']['session_timeout'] = int(new_config['session_timeout'])
        sessionSeconds = int(new_config['session_timeout']) * 60
        try:
            db.command("collMod", "sessions", index={'keyPattern': {'last_accessed':1},'expireAfterSeconds': sessionSeconds})
        except:
            db.sessions.ensure_index("last_accessed",expireAfterSeconds=sessionSeconds)
        if int(new_config['max_events']) > 15000:
            config['Webserver']['events']['maxResults'] = 15000
        else:
            config['Webserver']['events']['maxResults'] = int(new_config['max_events'])
        config['Database']['events']['max_age'] = int(new_config['max_age'])
        alertTimeout = int(new_config['max_age']) * 86400
        try:
            db.command("collMod", "alerts", index={'keyPattern': {'timestamp':1},'expireAfterSeconds': alertTimeout})
        except:
            db.alerts.ensure_index("timestamp",expireAfterSeconds=alertTimeout)
        config['Database']['events']['flow_max_age'] = int(new_config['flow_age'])
        flowTimeout = int(new_config['flow_age']) * 86400
        try:
            db.command("collMod", "flow", index={'keyPattern': {'timestamp':1},'expireAfterSeconds': flowTimeout})
        except:
            db.flow.ensure_index("timestamp",expireAfterSeconds=flowTimeout)
        config['Database']['events']['dns_max_age'] = int(new_config['dns_age'])
        dnsTimeout = int(new_config['dns_age']) * 86400
        try:
            db.command("collMod", "dns", index={'keyPattern': {'timestamp':1},'expireAfterSeconds': dnsTimeout})
        except:
            db.dns.ensure_index("timestamp",expireAfterSeconds=dnsTimeout)
        config['Database']['events']['temp_filter_age'] = int(new_config['temp_filter_age'])
        filterTimeout = int(new_config['temp_filter_age']) * 3600
        try:
            db.command("collMod", "filters", index={'keyPattern': {'temp_timestamp':1},'expireAfterSeconds': filterTimeout})
        except:
            db.filters.ensure_index("temp_timestamp",expireAfterSeconds=filterTimeout)

        return config

    def get_socket(self, channels):
        context = zmq.Context()
        log_client = context.socket(zmq.PUSH)
        log_client.set_hwm(10000)
        log_client.setsockopt(zmq.LINGER, 10000)
        log_client.connect(channels['logger'])
        return log_client


class MinervaLog(threading.Thread):
    def __init__(self, config, channels, logname):
        threading.Thread.__init__(self)
        self.channels = channels
        self.config = config
        self.logname = logname

    def run(self):
        #setup logger
        logger = getLogger("Minerva")
        if self.config['Logger']['level'] == 'INFO':
            logger.setLevel(INFO)
        else:
            logger.setLevel(DEBUG)
        if not os.path.exists(self.config['Logger']['logDir']):
            os.mkdir(self.config['Logger']['logDir'])
        logger_format = Formatter('%(asctime)s:%(levelname)s: %(message)s')
        handler = RotatingFileHandler(filename="%s/%s.log" % (self.config['Logger']['logDir'], self.logname), maxBytes=int(self.config['Logger']['maxSize']), backupCount=int(self.config['Logger']['maxCount']))
        handler.setFormatter(logger_format)
        logger.addHandler(handler)
        log = {
            "INFO": logger.info,
            "DEBUG": logger.debug,
            "ERROR": logger.error,
            "NONE": logger.critical
        }

        #setup ZMQ
        context = zmq.Context()
        log_queue = context.socket(zmq.PULL)
        log_queue.bind(self.channels['logger'])

        while True:
            try:
                if log_queue.poll(500):
                    msg = log_queue.recv_multipart()
                    if msg[0] == 'KILL':
                        log_queue.close()
                        #sys.exit()
                        break
                    log[msg[0]](msg[1])
            except:
                pass

    def get_socket(self):
        context = zmq.Context()
        log_client = context.socket(zmq.PUSH)
        log_client.connect(self.channels['logger'])
        return log_client

