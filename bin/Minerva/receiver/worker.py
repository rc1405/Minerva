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
import sys
import datetime
import json
import uuid

import M2Crypto
import pymongo
from pymongo.errors import BulkWriteError
import zmq
import yara
#import threading
import os
from multiprocessing import Process

from pytz import timezone
from dateutil.parser import parse

#class EventWorker(threading.Thread):
class EventWorker(Process):
    def __init__(self, minerva_core, channels, update_lock, action_file, sig_file):
        Process.__init__(self)
        self.config = minerva_core.conf
        self.core = minerva_core
        self.channels = channels
        self.logger = minerva_core.get_socket(channels)
        db = minerva_core.get_db()
        keys = db.certs.find_one({"type": "receiver"})
        key = keys['key']
        self.PUBCERT = keys['cert']
        self.PRIVKEY = M2Crypto.RSA.load_key_string(str(key))
        self.update_lock = update_lock
        self.action_file = action_file
        self.sig_file = sig_file
        self.certs = db.certs
        self.keys = db.keys
        self.channels['context'] = zmq.Context()

    def get_name(self):
        return "Process %s" % self.name

    def _decrypt_rsa(self, cert, enc_payload):
        CERT = M2Crypto.X509.load_cert_string(str(cert))
        PUBKEY = CERT.get_pubkey()
        RSA = PUBKEY.get_rsa()
        try:
            dmesg = self.PRIVKEY.private_decrypt(enc_payload.decode('base64'), M2Crypto.RSA.pkcs1_padding).decode('base64')
            dmesg = json.loads(dmesg)
            self.logger.send_multipart(['DEBUG','Worker RSA decryption success'])
        except:
            self.logger.send_multipart(['DEBUG','Worker RSA decryption failure'])
            return False
        return dmesg

    def _encrypt_aes_web(self, payload):
        aes_key = self.keys.find_one({"SERVER": "webserver"})
        try:
            self.logger.send_multipart(['DEBUG','Worker Webserver AES key exists'])
            aes_key = aes_key['KEY'].decode('base64')
        except:
            self.logger.send_multipart(['DEBUG','Worker Webserver AES key does not exists, generating one'])
            aes_key = os.urandom(32).encode('base64')
            self.keys.update_one({"SERVER": "webserver"},{"$set": { "KEY": aes_key }}, upsert=True)

        cipher = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=aes_key, iv=aes_key, op=1)
        enc_payload = cipher.update(payload) + cipher.final()
        return enc_payload.encode('base64')

    def _decrypt_aes(self, key, payload):
        try:
            key = key.decode('base64')
            cipher = M2Crypto.EVP.Cipher('aes_256_cbc', key=key, iv=key, op=0)
            events = json.loads(cipher.update(payload.decode('base64')) + cipher.final())
            self.logger.send_multipart(['DEBUG','Worker AES decryption success'])
            return events
        except:
            self.logger.send_multipart(['DEBUG','Worker AES decryption failure'])
            return False

    def _encrypt_rsa(self, cert, payload):
        CERT = M2Crypto.X509.load_cert_string(str(cert))
        PUBKEY = CERT.get_pubkey()
        RSA = PUBKEY.get_rsa()
        try:
       
            self.logger.send_multipart(['DEBUG','Worker RSA encryption success'])
            enc_payload = RSA.public_encrypt(payload, M2Crypto.RSA.pkcs1_padding).encode('base64')
            return enc_payload
        except Exception as e:
            self.logger.send_multipart(['DEBUG','Worker RSA encryption success'])
            return False

    def run(self):
        self.logger = self.core.get_socket(self.channels)
        self.channels['context'] = zmq.Context()
        work = self.channels['context'].socket(zmq.PULL)
        work_recv = work.recv_json

        for p in self.channels['receiver'].keys():
            work.connect(self.channels['receiver'][p])

        self.logger.send_multipart(['DEBUG','Worker listening to %i receivers' % len(self.channels['receiver'])])

        publisher = self.channels['context'].socket(zmq.PUSH)
        publisher.connect(self.channels['pub'])
        work_send = publisher.send_multipart

        self.logger.send_multipart(['DEBUG','Worker Connected to publisher'])

        receiver = self.channels['context'].socket(zmq.PUSH)
        receiver.connect(self.channels['worker_main'])

        self.logger.send_multipart(['DEBUG','Worker Connected to Worker Manager Thread Listener'])

        auth_checker = ClientAuth(self.core, self.channels)
        auth_check = auth_checker.check

        mongo = MongoInserter(self.core, self.channels)
        inserter = mongo.insert_data

        watcher = EventWatch(self.core, self.channels, self.update_lock, self.action_file, self.sig_file)
        
        json_loads = json.loads
        json_dumps = json.dumps
    
        count = 0

        while True:
            try:
                msg = work_recv()
                ID = str(msg['_id'])
                try:
                    if msg['_function'] == 'auth':
                        self.logger.send_multipart(['DEBUG','Worker received auth from %s' % ID])
                        is_auth = auth_check(ID, msg['_cert'])
                        work_send([ID, json.dumps({
                            "_cert": self.PUBCERT,
                            "_message": self._encrypt_rsa(msg['_cert'], json.dumps({
                                "_function": "auth",
                                "AESKEY": is_auth
                        }))})])
                        self.logger.send_multipart(['DEBUG','Worker sent auth to publisher'])
                except KeyError:
                    is_auth = auth_check(ID, msg['_cert'])
                    if is_auth:
                        denc_msg = self._decrypt_aes(is_auth, msg['_payload'])
                        try:
                            if denc_msg['_function'] == 'events':
                                self.logger.send_multipart(['DEBUG','Worker is sending back ack to %s' % ID])
                                work_send([ID, json.dumps({
                                    "_message": self._encrypt_rsa(msg['_cert'], json_dumps({
                                       "_function": "events",
                                       "status": "success"
                                    })),
                                })])

                                self.logger.send_multipart(['DEBUG','Worker Recieived events from %s' % ID])
                                watch_events = inserter(ID, denc_msg['events'], watcher.filter_check)
                                self.logger.close(linger=1000)
                                self.logger = self.core.get_socket(self.channels)
                                self.logger.send_multipart(['DEBUG','Worker Recieived watch events from %s' % ID])
                                watch_alerts = False
                                if len(watch_events) > 0:
                                    watch_alerts = list(watcher.watch(watch_events))
                                self.logger.send_multipart(['DEBUG','Worker has sent back ack to %s' % ID])
                                if watch_alerts:
                                    self.logger.send_multipart(['DEBUG','Worker has %i watchlist events from %s' % (len(watch_alerts), ID)])
                                    watch_events = inserter('receiver', watch_alerts, watcher.filter_check)


                            elif denc_msg['_function'] == 'PCAP':
                                if denc_msg['_action'] == 'request':
                                    self.logger.send_multipart(['DEBUG','Worker received PCAP reqeust for %s' % str(denc_msg['target'])])
                                    work_send([str(denc_msg['target']), json.dumps({
                                         "mid": denc_msg['target'], 
                                         "_payload": { 
                                             "action": "request",
                                             "request": denc_msg['request'], 
                                             "console": ID, 
                                             "request_id": denc_msg['request_id'],
                                             "_function": "PCAP"
                                         },
                                         "_function": "PCAP",
                                    })])

                                elif denc_msg['_action'] == 'reply':
                                    self.logger.send_multipart(['DEBUG','Worker received PCAP reply from %s' % ID])
                                    work_send([str(denc_msg['console']), json.dumps({
                                         "mid": denc_msg['console'], 
                                         "_payload": self._encrypt_aes_web(json_dumps(denc_msg)),
                                         "request_id": denc_msg['request_id'],
                                         "_function": "PCAP",
                                    })])
                                    self.logger.send_multipart(['DEBUG','Worker sending PCAP ack to %s' % ID])
                                    work_send([ID, json.dumps({
                                        "_message": self._encrypt_rsa(msg['_cert'], json_dumps({
                                           "_function": "PCAP_ACK",
                                           "status": "success"
                                        })),
                                    })])

                            elif denc_msg['_function'] == '_RECV_UPDATE':
                                self.logger.send_multipart(['DEBUG','Worker received watchlist update notification'])
                                receiver.send("UPDATE_YARA")

                            else:
                                self.logger.send_multipart(['DEBUG','Worker received unrecognized function from %s' % ID])
                                work_send([ID, json.dumps({
                                    "_function": "auth",
                                    "_cert": self.PUBCERT
                                })])
                                continue
                        except TypeError:
                            self.logger.send_multipart(['ERROR','Worker received unauthorized event from %s' % ID])
                            work_send([ID, json.dumps({
                                "_function": "auth",
                                "_cert": self.PUBCERT
                            })])
                    else:
                        self.logger.send_multipart(['ERROR','Worker received authorization failure from %s' % ID])
                        work_send([ID, json.dumps({
                            "_function": "auth",
                            "_cert": self.PUBCERT
                        })])

            #except Exception as e:
                #print('{}: {}'.format(e.__class__.__name__,e))
                #sys.exit()

            except ValueError:
                self.logger.send_multipart(['DEBUG','Worker encountered ValueError exception from %s' % ID])
                pass
            except KeyError:
                self.logger.send_multipart(['DEBUG','Worker encountered KeyError exception from %s' % ID])
                pass
            except KeyboardInterrupt:
                self.logger.send_multipart(['DEBUG','Shutting down worker'])
                sys.exit()

class MongoInserter(object):
    def __init__(self, minerva_core, channels):
        self.config = minerva_core.conf
        self.core = minerva_core
        self.logger = minerva_core.get_socket(channels)
        db = minerva_core.get_db()
        self.alerts = db.alerts
        self.flow = db.flow
        self.dns = db.dns
        self.certs = db.certs

    def insert_data(self, sensor, msg, filter_check):
        self.logger.send_multipart(['DEBUG','Worker mongo processing events from %s' % sensor])
        alert_events = []
        flow_events = []
        dns_events = []
        watch_events = []

        if len(msg) == 0:
            return []

        for event in msg:
            if isinstance(event, basestring):
                try:
                    event = json.loads(event)
                except ValueError:
                    self.logger.send_multipart(['DEBUG','Worker received Bad JSON event from %s' % sensor])
                    continue
                if isinstance(event, basestring):
                    try:
                        event = json.loads(event)
                    except:
                        self.logger.send_multipart(['DEBUG','Worker received Bad JSON event from %s' % sensor])
                        continue
            if sensor != 'receiver':
                event['sensor'] = sensor
            event['uuid'] = str(uuid.uuid4())
            if event['logType'] == 'alert':
                event['MINERVA_STATUS'] = 'OPEN'
                event = filter_check(event)
                timestamp = event['timestamp']
                try:
                    ts = parse(timestamp)
                    tz = timezone('UTC')
                    event['timestamp'] = ts.astimezone(tz)
                except ValueError:
                    event['timestamp'] = ts
                alert_events.append(event)
                if event['alert']['category'] != "minerva-watchlist":
                    try:
                        watch_events.append( {
                            "sensor": sensor, 
                            "uuid": event['uuid'], 
                            "_function": "watchlist",
                            "proto": event['proto'],
                            "src_ip": event['src_ip'], 
                            "src_port": event['src_port'], 
                            "dest_ip": event['dest_ip'], 
                            "dest_port": event['dest_port'], 
                            "type": "ip"
                        })
                    except KeyError:
                        watch_events.append( {
                            "sensor": sensor,
                            "uuid": event['uuid'],
                            "_function": "watchlist",
                            "proto": event['proto'],
                            "src_ip": event['src_ip'],
                            "dest_ip": event['dest_ip'],
                            "type": "ip"
                        })

            elif event['logType'] == 'flow':
                try:
                    tz = timezone('UTC')
                    ts = parse(event['timestamp'])
                    event['timestamp'] = ts.astimezone(tz)
                    start_time = parse(event['netflow']['start'])
                    event['netflow']['start'] = start_time.astimezone(tz)
                    stop_time = parse(event['netflow']['end'])
                    event['netflow']['end'] = stop_time.astimezone(tz)
                    flow_events.append(event)
                except:
                    continue
                try:
                    watch_events.append( {
                        "sensor": sensor,
                        "uuid": event['uuid'],
                        "_function": "watchlist",
                        "proto": event['proto'],
                        "src_ip": event['src_ip'],
                        "src_port": event['src_port'],
                        "dest_ip": event['dest_ip'],
                        "dest_port": event['dest_port'],
                        "type": "ip"
                    })
                except KeyError:
                        watch_events.append( {
                            "sensor": sensor,
                            "uuid": event['uuid'],
                            "_function": "watchlist",
                            "proto": event['proto'],
                            "src_ip": event['src_ip'],
                            "dest_ip": event['dest_ip'],
                            "type": "ip"
                        })


            elif event['logType'] == 'dns':
                timestamp = event['timestamp']
                try:
                    ts = parse(timestamp)
                    tz = timezone('UTC')
                    event['timestamp'] = ts.astimezone(tz)
                except:
                    continue
                dns_events.append(event)
                dns_watch = {
                    "sensor": sensor, 
                    "uuid": event['uuid'], 
                    "_function": "watchlist",
                    "proto": event['proto'],
                    "src_ip": event['src_ip'], 
                    "src_port": event['src_port'], 
                    "dest_ip": event['dest_ip'], 
                    "dest_port": event['dest_port'], 
                    "type": "ip"
                }
                if event['dns']['type'] == 'answer':
                    if 'rdata' in event['dns']:
                        dns_watch['domain'] = event['dns']['rdata']
                watch_events.append(dns_watch)

        while True:
            try:
                if len(alert_events) > 0:
                    self.alerts.insert_many(alert_events, ordered=False)
                    self.logger.send_multipart(['DEBUG','Worker mongo inserting %i alert events from %s' % (len(alert_events), sensor)])
                    alert_events = []
                if len(flow_events) > 0:
                    self.flow.insert_many(flow_events, ordered=False)
                    self.logger.send_multipart(['DEBUG','Worker mongo inserting %i flow events from %s' % (len(flow_events), sensor)])
                    flow_events = []
                if len(dns_events) > 0:
                    self.dns.insert_many(dns_events, ordered=False)
                    self.logger.send_multipart(['DEBUG','Worker mongo inserting %i dns events from %s' % (len(dns_events), sensor)])
                    dns_events = []

                if len(alert_events) + len(flow_events) + len(dns_events) == 0:
                    break
            except BulkWriteError:
                continue
        try:
            if sensor != "receiver":
                self.certs.update({"SERVER": sensor}, {
                    "$set": {
                        "last_event":  datetime.datetime.utcnow()
                    }
                })
                #self.logger.send_multipart(['DEBUG','Worker mongo passing on %i events from %s for additional filtering' % (len(watch_events), sensor)])

        except Exception as e:
            #pass
            #print('{}: {}'.format(e.__class__.__name__,e))
            return watch_events

        return watch_events

class ClientAuth(object):
    def __init__(self, minerva_core, channels):
        self.config = minerva_core.conf
        self.core = minerva_core
        self.logger = minerva_core.get_socket(channels)
        db = minerva_core.get_db()
        self.certs = db.certs
        self.keys = db.keys

    def check(self, mid, cert):
        mid = mid.split('|-_')[0]
        sensor = self.certs.find_one({"SERVER": mid})
        self.logger.send_multipart(['DEBUG','Worker starting authorization checks for %s' % mid])
        try:
            if sensor['CERT'] == cert and sensor['STATUS'] == 'APPROVED':
                self.logger.send_multipart(['DEBUG','Worker authorization success for %s' % mid])
                aes_key = self.keys.find_one({"SERVER": mid})
                if not aes_key:
                    self.logger.send_multipart(['DEBUG','Worker generating AES key for %s' % mid])
                    aes_key = os.urandom(32).encode('base64')
                    self.keys.update_one({"SERVER": mid},{"$set": { "KEY": aes_key, "timestamp": datetime.datetime.utcnow() }}, upsert=True)
                    return aes_key
                else:
                    self.logger.send_multipart(['DEBUG','Worker AES key for %s exists' % mid])
                    return aes_key['KEY']
            elif sensor['CERT'] == cert and sensor['STATUS'] != 'APPROVED':
                self.logger.send_multipart(['DEBUG','Worker authorization failed for %s' % mid])
                return False
            elif sensor['CERT'] != cert:
                self.logger.send_multipart(['DEBUG','Worker certificate changed for %s' % mid])
                self.certs.update({ "SERVER": mid }, {
                  "$set": {
                    "last_modified":  datetime.datetime.utcnow(),
                    "SERVER": mid,
                    "STATUS": "CERT_CHANGED",
                    "CERT": cert
                  }
                }, upsert=True)
                return False
            return False
        except TypeError:
            self.logger.send_multipart(['DEBUG','Worker authorization failed for %s, checking cert' % mid])
            sensor = self.certs.find_one({"CERT": cert})
            if sensor:
                self.logger.send_multipart(['ERROR','Worker certificate for %s matches existing entry' % mid])
                self.certs.update({ "SERVER": mid }, {
                  "$set": {
                    "last_modified":  datetime.datetime.utcnow(),
                    "SERVER": mid, 
                    "STATUS": "CERT_COPIED", 
                    "CERT": cert,
                    "type": "sensor"
                  }
                }, upsert=True)
                self.certs.update({ "SERVER": sensor['SERVER'] }, {
                  "$set": {
                    "last_modified":  datetime.datetime.utcnow(),
                    "SERVER": sensor['SERVER'],
                    "STATUS": "CERT_COPIED"
                  }
                })
            else:
                self.logger.send_multipart(['ERROR','Worker authorization failed for %s' % mid])
                self.certs.update({ "SERVER": mid }, {
                  "$set": {
                    "time_created":  datetime.datetime.utcnow(),
                    "last_modified":  datetime.datetime.utcnow(),
                    "SERVER": mid, 
                    "STATUS": "NOT_APPROVED", 
                    "CERT": cert,
                    "type": "sensor"
                  }
                }, upsert=True)
            return False

class EventWatch(object):
    def __init__(self, minerva_core, channels, update_lock, action_file, sig_file):
        self.config = minerva_core.conf
        self.logger = minerva_core.get_socket(channels)
        db = minerva_core.get_db()
        self.dns = db.dns
        self.alerts = db.alerts
        #setup YARA settings
        self.update_lock = update_lock
        self.action_file = action_file
        self.sig_file = sig_file
        self.action = yara.compile(action_file)
        self.sig = yara.compile(sig_file)
        self.last_update = int(time.time())
        self.update_thres = self.config['Event_Receiver']['watchlist_update_sec']

    def update_yara(self):
        if self.update_lock.acquire(timeout=.1):
            self.logger.send_multipart(['DEBUG','Worker updating watchlist and rule filters'])
            self.trigger = yara.compile(self.action_file)
            self.action = yara.compile(self.sig_file)
            self.update_lock.release()
            self.last_update = int(time.time())
            self.logger.send_multipart(['DEBUG','Worker completed updating watchlist and rule filters'])
        return

    def watch(self, events):
        if (int(time.time()) - self.last_update) > self.update_thres:
            self.update_yara()
        for event in events:
            alerts = self.sig.match(data=json.dumps(event))
            if alerts:
                for a in alerts:
                    cat, hit = str(a).split('__')
                    alert_type, priority = cat.split('_')
                    match = hit.replace('_','.')
                    self.logger.send_multipart(['DEBUG','Worker received watchlist hit from %s' % event['sensor']])
                    yield self.fire_alert(event, match, alert_type, priority)

    def filter_check(self, event):
        if (int(time.time()) - self.last_update) > self.update_thres:
            self.update_yara()
        matches = self.action.match(data=json.dumps(event))
        if matches:
            self.logger.send_multipart(['DEBUG','Worker received rule filter match from %s' % event['sensor']])
            for m in matches:
                rule = str(m).split('__')
                if rule[0] == 'P':
                    if rule[1] == 'inc':
                        sev = event['alert']['severity'] + int(rule[2])
                        if sev > 5:
                            sev = 5
                    else:
                        sev = event['alert']['severity'] - int(rule[2])
                        if sev < 1:
                            sev = 1
                    event['alert']['severity'] = sev
                else:
                    if rule[1] == 'C':
                        event['MINERVA_STATUS'] = 'CLOSED'
                    elif rule[1] == 'E':
                        event['MINERVA_STATUS'] = 'ESCALATED'
                    else:
                        event['MINERVA_STATUS'] = 'OPEN'
        return event
                    

 
    def fire_alert(self, event, match, alert_type, priority):
        new_event = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "payload_printable" : "",
            "event_type" : "alert",
            "proto" : event['proto'],
            "sensor": event['sensor'],
            "alert" : {
                "category" : "minerva-watchlist",
                "severity" : int(priority),
                "rev" : 1,
                "gid" : 999,
                "signature" : "Minerva Watchlist %s - %s" % (alert_type, match),
                "signature_id" : 9000000
            },
            "src_ip" : event['src_ip'],
            "logType" : "alert",
            "packet" : "",
            "dest_ip" : event['dest_ip'],
            "payload" : "",
            "MINERVA_STATUS" : "OPEN",
        }
        if not new_event['proto'] == 'ICMP':
            new_event['src_port'] = event['src_port']
            new_event['dest_port'] = event['dest_port']
        return json.dumps(new_event)
