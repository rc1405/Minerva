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

import os
import time
import platform
import subprocess
import shutil
import sys
from tempfile import NamedTemporaryFile
from ws4py.websocket import WebSocket
from ws4py.server.cherrypyserver import WebSocketPlugin, WebSocketTool
from ws4py.messaging import TextMessage

import json
import cherrypy
from jinja2 import Environment, FileSystemLoader

from Minerva import core
#from Minerva.server import alert_console, alert_flow, sensors, Users, HandleRequests, event_filters, MinervaSignatures, watchlist, dns
from Minerva.server import *

env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(sys.argv[0]),'templates')))

class BroadcastWebSocketHandler(WebSocket):
    def received_message(self, m):
        print('broadcast sock handler: ')
        print(m)
        cherrypy.engine.publish('websocket-broadcast', m)


'''
class MinervaEventPlugin(WebSocketPlugin):
    def __init__(self, bus):
        WebSocketPlugin.__init__(self, bus)
        self.clients = {}

    def start(self):
        WebSocketPlugin.start(self)
        self.bus.subscribe('add-client', self.add_client)
        self.bus.subscribe('get-client', self.get_client)
        self.bus.subscribe('del-client', self.del_client)

    def stop(self):
        WebSocketPlugin.stop(self)
        self.bus.unsubscribe('add-client', self.add_client)
        self.bus.unsubscribe('get-client', self.get_client)
        self.bus.unsubscribe('del-client', self.del_client)

    def add_client(self, name, websocket):
        self.clients[name] = websocket

    def get_client(self, name):
        return self.clients[name]

    def del_client(self, name):
        del self.clients[name]
'''

class MinervaPlugin(WebSocketPlugin):
    def __init__(self, bus, core):
        WebSocketPlugin.__init__(self, bus)
        self.clients = {}
        self.Users = Users(core)
        self.core = core

    def start(self):
        WebSocketPlugin.start(self)
        self.bus.subscribe('add-client', self.add_client)
        self.bus.subscribe('get-client', self.get_client)
        self.bus.subscribe('del-client', self.del_client)
        self.bus.subscribe('get-perms', self.get_perms)
        self.bus.subscribe('get-core', self.get_core)
        self.bus.subscribe('get-username', self.get_username)

    def stop(self):
        WebSocketPlugin.stop(self)
        self.bus.unsubscribe('add-client', self.add_client)
        self.bus.unsubscribe('get-client', self.get_client)
        self.bus.unsubscribe('del-client', self.del_client)
        self.bus.unsubscribe('get-perms', self.get_perms)
        self.bus.unsubscribe('get-core', self.get_core)
        self.bus.unsubscribe('get-username', self.get_username)

    def add_client(self, name, websocket):
        self.clients[name] = websocket

    def get_client(self, name):
        return self.clients[name]

    def del_client(self, name):
        del self.clients[name]

    def get_perms(self, session_id):
        return self.Users.get_permissions(session_id)

    def get_username(self, session_id):
        return self.Users.get_username(session_id)

    def get_core(self):
        return self.core

class MinervaWebSocketHandler(WebSocket):
    def opened(self):
        cherrypy.engine.publish('add-client', self.session_id, self)
        #perm_return = cherrypy.engine.publish('get-perms', request['session_id']).pop()
        #core = cherrypy.engine.publish('get-core').pop()
        # check permissions
        # send events
        #alerts.get_alerts()
        # send stats
           
        
    def received_message(self, m):
        print(m)
        request = json.loads(m.data)

        perm_return = cherrypy.engine.publish('get-perms', request['session_id']).pop()
        client = cherrypy.engine.publish('get-client', request['session_id']).pop()
        core = cherrypy.engine.publish('get-core').pop()

        '''
        if 'PasswordReset' in perm_return:

        elif 'newLogin' in perm_return:
            #delete socket
        '''

        if request['action'] == 'form':
            if request['form'] == 'console':
                alerts = alert_console(core)
                results = alerts.get_alerts()
                client.send(json.dumps({"action": "new_events", "events": results}))

                results = {
                  "action": "refresh_chart",
                  "chart": "ip_count",
                  "data": alerts.get_ip_count()
                }
                client.send(json.dumps(results))

                results = {
                  "action": "refresh_chart",
                  "chart": "ip_bytes",
                  "data": alerts.get_ip_volume()
                }
                client.send(json.dumps(results))

                results = {
                  "action": "refresh_chart",
                  "chart": "dns_count",
                  "data": alerts.get_dns_count()
                }
                client.send(json.dumps(results))

                results = {
                  "action": "refresh_chart",
                  "chart": "sensor_vol",
                  "data": alerts.get_sensor_volume()
                }
                client.send(json.dumps(results))
                
                results = {
                  "action": "refresh_chart",
                  "chart": "http_count",
                  "data": alerts.get_http_count()
                }
                client.send(json.dumps(results))

                #print(json.dumps(alerts.get_ip_count(), indent=1))
                #print('------------------------------------------------------------------------------------------------------------')
                #print(json.dumps(alerts.get_ip_volume(), indent=1))
                #print('------------------------------------------------------------------------------------------------------------')
                #print(json.dumps(alerts.get_dns_count(), indent=1))
        elif request['action'] == 'refresh_chart':
            if request['chart'] == 'ip_count':
                print('ip count')
                alerts = alert_console(core)
                results = {
                  "action": "refresh_chart",
                  "chart": "ip_count",
                  "data": alerts.get_ip_count()
                }
                client.send(json.dumps(results))
                print(json.dumps(results))
                print('sent refresh back')
            elif request['chart'] == 'ip_bytes':
                alerts = alert_console(core)
                results = {
                  "action": "refresh_chart",
                  "chart": "ip_bytes",
                  "data": alerts.get_ip_volume()
                }
                client.send(json.dumps(results))
            elif request['chart'] == 'dns_count':
                alerts = alert_console(core)
                results = {
                  "action": "refresh_chart",
                  "chart": "dns_count",
                  "data": alerts.get_dns_count()
                }
                client.send(json.dumps(results))
                print(json.dumps(results))
            elif request['chart'] == 'sensor_vol':
                alerts = alert_console(core)
                results = {
                  "action": "refresh_chart",
                  "chart": "sensor_vol",
                  "data": alerts.get_sensor_volume()
                }
                client.send(json.dumps(results))
            elif request['chart'] == 'http_count':
                alerts = alert_console(core)
                results = {
                  "action": "refresh_chart",
                  "chart": "http_count",
                  "data": alerts.get_http_count()
                }
                client.send(json.dumps(results))
                
        elif request['action'] == 'investigate':

            if 'console' in perm_return or 'responder' in perm_return:
                print(request)
                alert = alert_console(core)
                #sigs = MinervaSignatures(core)

                #items = flow.get_flow(request['uuids'])
                results = alert.investigate(request['uuids'])
                print(results)

                #context_dict = {}
                #context_dict['items'] = items
                #context_dict['comments'] = alert.get_comments(request['events'])
                #context_dict['signatures'] = sigs.get_signature(request['events'])

                client.send(json.dumps({
                    "action": "investigate",
                    "events": results
                }))


        elif request['action'] == 'close':
            cherrypy.engine.publish('websocket-broadcast', m)
            client.send("custom mesage")

        '''
            if 'console' in perm_return or 'responder' in perm_return:
                alerts = alert_console(core)
                username = cherrypy.engine.publish('get-username', request['session_id']).pop()
                alerts.close_alert(request['events'], request['comments'], username)

                client.send("something of success")

            else:
                #some error

        elif request['action'] == 'escalate':

            if 'console' in perm_return:

                username =  cherrypy.engine.publish('get-username', request['session_id']).pop()
                alerts = alert_console(core)
                alerts.escalate_alert(request['events'], request['comments'], username)

                #send response

            else:
                raise cherrypy.HTTPError(403)

        elif request['action'] == 'comment':

            if 'console' in perm_return or 'responder' in perm_return:

                alerts = alert_console(core)
                username = cherrypy.engine.publish('get-username', request['session_id']).pop()
                alerts.add_comments(request['events'], request['comments'], username)

                #send back

            else:
                # some error

        elif request['action'] == 'pcap':

            if 'console' in perm_return or 'responder' in perm_return:

                pcaps = HandleRequests(core)

                #todo, zip up multiple file and return that
                if request['yype'] == 'flow':
                    pcap = pcaps.flowPCAP(request['events'])

                else:
                    pcap = pcaps.alertPCAP(request['events'])

                if isinstance(pcap, basestring):
                    #send failure
                    return '<script type="text/javascript">window.alert("%s");window.close();</script>' % pcap

                else:
                    # tell to download
                    tmp = NamedTemporaryFile(mode='w+b', suffix='.pcap')
                    tmp.write(pcap.read())
                    tmp.flush()
                    cherrypy.session['pcap_file'] = tmp
                    return '<script type="text/javascript">location="/download";</script>'

            else:
                raise cherrypy.HTTPError(404)


        else:
            #some error
        '''

    def closed(self, code, reason="A client left the room without a proper explanation."):
        cherrypy.engine.publish('del-client', self.session_id)
        cherrypy.engine.publish('websocket-broadcast', TextMessage(reason))





class Webserver(object):
    def __init__(self, minerva_core):
        self.configs = minerva_core.conf['Webserver']
        self.sizeLimit = self.configs['events']['maxResults']
        self.minerva_core = minerva_core
    
    #Log in/out functions
    @cherrypy.expose
    def login(self, **kwargs):
        authUser = Users(self.minerva_core)
        if cherrypy.request.method == 'POST':
            request = cherrypy.request.params
            if authUser.login(request['username'], request['password'], cherrypy.session ):
                if 'prev_page' in cherrypy.session.keys():
                    prev_page = cherrypy.session['prev_page']
                    raise cherrypy.HTTPRedirect(prev_page)
                permissions = authUser.get_permissions(cherrypy.session.get('SESSION_KEY'))
                if 'console' in permissions:
                    raise cherrypy.HTTPRedirect("/")
                elif 'responder' in permissions:
                    raise cherrypy.HTTPRedirect("/responder")
                elif 'sensor_admin' in permissions:
                    raise cherrypy.HTTPRedirect("/sensors")
                elif 'user_admin' in permissions:
                    raise cherrypy.HTTPRedirect("/users")
                elif 'server_admin' in permissions:
                    raise cherrypy.HTTPRedirect("/")
                elif 'PasswordReset' in permissions:
                    raise cherrypy.HTTPRedirect("/profile")
                else:
                    raise cherrypy.HTTPError(403)
            else:
                return '<script type="text/javascript">window.alert("Invalid Username or Pasword");location="/login";</script>'
        else:
            context_dict = {}
            context_dict['motd'] = self.configs['web']['motd']
            tmp = env.get_template('login.jinja')
            return tmp.render(context_dict)
    
    @cherrypy.expose
    def logout(self, **kwargs):
        if 'SESSION_KEY' in cherrypy.session.keys():
            del cherrypy.session['SESSION_KEY']
        raise cherrypy.HTTPRedirect("/")
    
    '''Start of Minerva Web Pages'''

    @cherrypy.expose
    def responder(self):
        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = "/responder"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'responder' in perm_return:
            context_dict = {}
            alerts = alert_console(self.minerva_core)
            numFound, items_found = alerts.get_escalated_alerts()
            context_dict['numFound'] = numFound
            context_dict['items_found'] = items_found
            context_dict['sizeLimit'] = self.sizeLimit
            context_dict['form'] = 'responder'
            context_dict['title'] = 'Escalation'
            context_dict['permissions'] = perm_return
            tmp = env.get_template('console.jinja')
            return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)


    @cherrypy.expose
    def about(self):
        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = '/about'

        if not 'SESSION_KEY' in cherrypy.session.keys():
            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')

        else:
            context_dict = {}
            context_dict['permissions'] = perm_return
            context_dict['form'] = 'about'
            tmp = env.get_template('about.jinja')
            return tmp.render(context_dict)


    '''Start of Pages with post/response functionality'''
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def investigate(self, **kwargs):
        if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 
                                                 'post_request' in cherrypy.session):
            
            user = Users(self.minerva_core)

            if not 'SESSION_KEY' in cherrypy.session.keys():
               cherrypy.session['prev_page'] = '/investigate'
               cherrypy.session['post_request'] = cherrypy.request.json
               raise cherrypy.HTTPRedirect('/login')

            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

            if 'PasswordReset' in perm_return:
                if cherrypy.request.method == 'POST':
                    cherrypy.session['post_request'] = cherrypy.request.json
                    cherrypy.session['prev_page'] = '/investigate'

                raise cherrypy.HTTPRedirect('/profile')

            elif 'console' in perm_return or 'responder' in perm_return:
                flow = alert_flow(self.minerva_core)
                alert = alert_console(self.minerva_core)
                sigs = MinervaSignatures(self.minerva_core)

                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json

                items = flow.get_flow(request['events'])

                context_dict = {}
                context_dict['items'] = items
                context_dict['form'] = request['formType']
                context_dict['comments'] = alert.get_comments(request['events'])
                context_dict['signatures'] = sigs.get_signature(request['events'])

                tmp = env.get_template('investigate.jinja')
                return tmp.render(context_dict)

            elif 'newLogin' in perm_return:
                cherrypy.session['prev_page'] = '/investigate'
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')

            else:
                raise cherrypy.HTTPError(403)

        else:
            raise cherrypy.HTTPError(404)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def event_filters(self, **kwargs):

        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = '/event_filters'

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        elif 'event_filters' in perm_return:
            filters = event_filters(self.minerva_core)
            context_dict = {}

            if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 
                                                     'post_request' in cherrypy.session.keys()):
                
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json

                username = user.get_username(cherrypy.session.get('SESSION_KEY'))

                if request['req_type'] == 'keep':
                    filters.change_filter(request['events'], 'keep')

                    raise cherrypy.HTTPRedirect('/event_filters')

                elif request['req_type'] == 'delete':
                    filters.change_filter(request['events'], 'delete')

                    raise cherrypy.HTTPRedirect('/event_filters')

                elif request['req_type'] == 'new_filter':
                    if request['application'] == 'incoming' or request['application'] == 'both':
                        filters.add_filter(request)

                    if request['application'] == 'existing' or request['application'] == 'both':
                        filters.change_alerts(request, username)

                    raise cherrypy.HTTPRedirect('/event_filters')

                else:
                    context_dict['new_filter'] = filters.get_alert_data(request['event'])

            numFound, items_found = filters.get_filters()
            context_dict['numFound'] = numFound
            context_dict['items_found'] = items_found
            context_dict['form'] = 'filters'
            context_dict['permissions'] = perm_return
            context_dict['sizeLimit'] = self.sizeLimit
            tmp = env.get_template('filters.jinja')
            return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')
        else:

            raise cherrypy.HTTPError(403)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def alerts(self, **kwargs):
        user = Users(self.minerva_core)

        if 'prev_page' in cherrypy.session and 'alert_search' in cherrypy.session:
            if cherrypy.session['prev_page'] == '/alerts' and not 'get_request' in cherrypy.session:
                del cherrypy.session['alert_search']

        cherrypy.session['prev_page'] = '/alerts'

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['get_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'console' in perm_return or 'responder' in perm_return:
            context_dict = { 'numFound': 0 }
            if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and (
                'get_request' in cherrypy.session or 'alert_search' in cherrypy.session)):
                
                alert = alert_console(self.minerva_core)

                if 'alert_search' in cherrypy.session:
                    request = cherrypy.session['alert_search']
                    del cherrypy.session['alert_search']
                    numFound, items_found, orig_search = alert.search_alerts(request, orig_search=True)

                else:
                    if 'get_request' in cherrypy.session.keys():
                        request = cherrypy.session['get_request']
                        del cherrypy.session['get_request']

                    else:
                        request = cherrypy.request.json

                    numFound, items_found, orig_search = alert.search_alerts(request)

                context_dict['items_found'] = items_found
                context_dict['numFound'] = numFound
                context_dict['orig_search'] = orig_search
                cherrypy.session['alert_search'] = orig_search

            sigs = MinervaSignatures(self.minerva_core)
            context_dict['classtypes'] = sigs.get_classtypes()
            context_dict['form'] = 'alerts'
            context_dict['permissions'] = perm_return
            context_dict['sizeLimit'] = self.sizeLimit
            tmp = env.get_template('alerts.jinja')
            return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            cherrypy.session['get_request'] = cherrypy.request.params
            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def flow(self, **kwargs):
        user = Users(self.minerva_core)

        if 'prev_page' in cherrypy.session and 'flow_search' in cherrypy.session:
            if cherrypy.session['prev_page'] == '/flow' and not 'get_request' in cherrypy.session:
                del cherrypy.session['flow_search']

        cherrypy.session['prev_page'] = "/flow"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'console' in perm_return or 'responder' in perm_return:
            context_dict = {'numFound': 0}

            if (cherrypy.request.method == 'GET' and (
                'flow_search' in cherrypy.session.keys() or 
                'post_request' in cherrypy.session.keys())) or \
                cherrypy.request.method == 'POST':

                flow = alert_flow(self.minerva_core)

                if 'flow_search' in cherrypy.session:
                    request = cherrypy.session['flow_search']
                    del cherrypy.session['flow_search']
                    numFound, items_found, orig_search = flow.search_flow(request, orig_search=True)

                else:
                    if 'post_request' in cherrypy.session.keys():
                        request = cherrypy.session['post_request']
                        del cherrypy.session['post_request']

                    else:
                        request = cherrypy.request.json

                    numFound, items_found, orig_search = flow.search_flow(request)

                context_dict['items_found'] = items_found
                context_dict['numFound'] = numFound
                context_dict['orig_search'] = orig_search
                cherrypy.session['flow_search'] = orig_search

            context_dict['form'] = 'flow'
            context_dict['permissions'] = perm_return
            context_dict['sizeLimit'] = self.sizeLimit
            tmp = env.get_template('flow.jinja')
            return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['port_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def dns(self, **kwargs):
        user = Users(self.minerva_core)

        if 'prev_page' in cherrypy.session and 'dns_search' in cherrypy.session:
            if cherrypy.session['prev_page'] == '/dns' and not 'get_request' in cherrypy.session:
                del cherrypy.session['dns_search']

        cherrypy.session['prev_page'] = "/dns"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'console' in perm_return or 'responder' in perm_return:
            context_dict = {'numFound': 0}

            if (cherrypy.request.method == 'GET' and (
                'dns_search' in cherrypy.session.keys() or 'post_request' in cherrypy.session.keys())) \
                or cherrypy.request.method == 'POST':

                dns_records = dns(self.minerva_core)

                if 'dns_search' in cherrypy.session:
                    request = cherrypy.session['dns_search']
                    del cherrypy.session['dns_search']
                    numFound, items_found, orig_search = dns_records.search_dns(request, orig_search=True)

                else:
                    if 'post_request' in cherrypy.session.keys():
                        request = cherrypy.session['post_request']
                        del cherrypy.session['post_request']

                    else:
                        request = cherrypy.request.json

                    numFound, items_found, orig_search = dns_records.search_dns(request)

                context_dict['items_found'] = items_found
                context_dict['numFound'] = numFound
                context_dict['orig_search'] = orig_search
                cherrypy.session['dns_search'] = orig_search

            '''
            dns_records = dns(self.minerva_core)
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json

                cherrypy.session['dns_search'] = dns_records.get_orig_search(request)
                raise cherrypy.HTTPRedirect('/dns')

            if 'dns_search' in cherrypy.session:
                request = cherrypy.session['dns_search']
                del cherrypy.session['dns_search']
                numFound, items_found, orig_search = dns_records.search_dns(request, orig_search=True)

                context_dict['items_found'] = items_found
                context_dict['numFound'] = numFound
                context_dict['orig_search'] = orig_search
                cherrypy.session['dns_search'] = orig_search'''


            context_dict['form'] = 'dns'
            context_dict['permissions'] = perm_return
            context_dict['sizeLimit'] = self.sizeLimit
            tmp = env.get_template('dns.jinja')
            return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['port_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def sensors(self, **kwargs):
        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = "/sensors"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'sensor_admin' in perm_return:
            if (cherrypy.request.method == 'GET' and 
                'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json

                sensor = sensors(self.minerva_core)
                sensor.update(request['sensors'],request['action'])

            context_dict = {}
            sensor = sensors(self.minerva_core)
            items_found = sensor.get_sensors()
            context_dict['items_found'] = items_found
            context_dict['form'] = 'sensors'
            context_dict['permissions'] = perm_return
            tmp = env.get_template('sensors.jinja')
            return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)

    @cherrypy.expose
    def signatures(self, **kwargs):
        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = "/signatures"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            raise cherrypy.HTTPRedirect('/profile')

        elif 'sensor_admin' in perm_return:
            if cherrypy.request.method == 'GET':
                context_dict = {}
                context_dict['form'] = 'signatures'
                context_dict['permissions'] = perm_return
                tmp = env.get_template('signatures.jinja')
                return tmp.render(context_dict)
            elif cherrypy.request.method == 'POST':
                lcHDRS = {}
                for key, val in cherrypy.request.headers.iteritems():
                    lcHDRS[key.lower()] = val
                incomingBytes = lcHDRS = int(lcHDRS['content-length'])
                sig = MinervaSignatures(self.minerva_core)
                file_count, good_sigs, bad_sigs = sig.process_files(kwargs['signature_file'])
                if isinstance(file_count, basestring):
                    return '<script type="text/javascript">window.alert("{}")'.format(ret_val) \
                           + ';location="/signatures";</script>'
                else:
                    return '<script type="text/javascript">window.alert("%i Files Checked.'.format(file_count) \
                           + '{} Signatures Processed.  {} Signatures Failed");'.format(good_sigs, bad_sigs) \
                           + 'location="/signatures";</script>' 

        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def users(self, **kwargs):
        users = Users(self.minerva_core)
        cherrypy.session['prev_page'] = "/users"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        perm_return =  users.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/profile')
        
        elif 'user_admin' in perm_return:

            retstatus = 'None'

            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request'] 
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json

                if request['updateType'] == 'new_user':
                    retstatus = users.create_user(
                        request['username'],
                        request['password'],
                        request['console'],
                        request['responder'],
                        request['event_filters'],
                        request['sensor_admin'],
                        request['user_admin'],
                        request['server_admin'],
                        request['enabled']
                    )

                elif request['updateType'] == 'editUser':
                    retstatus = users.modify_user(
                        request['username'],
                        request['password'],
                        request['console'],
                        request['responder'],
                        request['event_filters'],
                        request['sensor_admin'],
                        request['user_admin'],
                        request['server_admin'],
                        request['enabled']
                    )

                elif request['updateType'] == 'updatePerms':
                    retstatus = users.changePerms(
                        request['username'],
                        request['console'],
                        request['responder'],
                        request['event_filters'],
                        request['sensor_admin'],
                        request['user_admin'],
                        request['server_admin'],
                        request['enabled']
                    )

            
            if retstatus == "Password Check Failed":
                ret_string = '"New Password does not meet strength Requirements: ' \
                              + 'lowercase, {} uppercase, {} numbers, {} special characters"'.format(
                                  self.configs['web']['password_requirements']['lower_count'],
                                  self.configs['web']['password_requirements']['upper_count'],
                                  self.configs['web']['password_requirements']['digit_count'],
                                  self.configs['web']['password_requirements']['special_count']
                              )
                return ret_string

            elif retstatus != "None":
                return_msg =  '%s' % retstatus
                return return_msg

            context_dict = {}
            context_dict['items_found'] = users.getAllUsers()
            context_dict['form'] = 'usermanagement'
            context_dict['ReturnStatus'] = retstatus 
            context_dict['permissions'] = perm_return
            tmp = env.get_template('users.jinja')
            return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def config(self, **kwargs):
        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = "/config"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'server_admin' in perm_return:
            if (cherrypy.request.method == 'GET' and 
                'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                
                if 'post_reqeust' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json

                server_config = core.MinervaConfigs()
                new_config = server_config.parse_web_configs(request)
                out_tmp = env.get_template('minerva.jinja')
                base_dir = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), os.pardir)
                shutil.copy(os.path.join(base_dir,'etc','minerva.yaml'),os.path.join(base_dir,'etc','minerva.yaml.bkup'))
                out_yaml = open(os.path.join(base_dir,'etc','minerva.yaml'), 'w')
                out_yaml.write(out_tmp.render({"config": new_config}))
                out_yaml.close()
                return_msg =  'Changes Saved.  A restart is required to take full effect'
                return return_msg

            else:
                context_dict = {}
                context_dict['config'] = self.minerva_core.conf
                context_dict['form'] = 'server_admin'
                context_dict['permissions'] = perm_return
                tmp = env.get_template('config.jinja')
                return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)

    
    @cherrypy.expose
    def profile(self, **kwargs):
        user = Users(self.minerva_core)

        if not 'SESSION_KEY' in cherrypy.session.keys():
            raise cherrypy.HTTPRedirect('/login')

        if cherrypy.request.method == 'POST':
            request = cherrypy.request.params

            if request['newPassword'] != request['newPassword2']:
                return '<script type="text/javascript">window.alert("New Passwords do not match");location="/profile";</script>'

            ret_status = user.changePW(cherrypy.session['SESSION_KEY'], request['currentPW'], request['newPassword'])

            if ret_status == 'success':
                return '<script type="text/javascript">window.alert("Password Successfully Changed");location="/profile";' \
                       + '</script>'

            elif ret_status == 'badOldPass':
                return '<script type="text/javascript">window.alert("Current Password is incorrect");location="/profile";' \
                       + '</script>'

            elif ret_status == 'newLogin':
                return '<script type="text/javascript">window.alert("Session Expired, Please log in with Previous' \
                       + 'Password");location="/login";</script>'

            elif ret_status == "Password Check Failed":
                ret_string = '<script type="text/javascript">window.alert("New Password does not meet strength' \
                              + 'Requirements: {} lowercase, {} uppercase, {} numbers, {} special characters");' \
                              + 'location="/profile";</script>'.format(
                                  self.configs['web']['password_requirements']['lower_count'],
                                  self.configs['web']['password_requirements']['upper_count'],
                                  self.configs['web']['password_requirements']['digit_count'],
                                  self.configs['web']['password_requirements']['special_count'] 
                              )

                return ret_string

        else:
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

            if 'newLogin' in perm_return:
                raise cherrypy.HTTPRedirect('/login')

            else:
                context_dict = {}
                context_dict['form'] = 'profile'
                context_dict['permissions'] = perm_return
                tmp = env.get_template('profile.jinja')
                return tmp.render(context_dict)


    @cherrypy.expose
    def watchlist(self, **kwargs):
        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = "/watchlist"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.params

            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.params

            raise cherrypy.HTTPRedirect('/profile')

        elif 'event_filters' in perm_return:
            watch = watchlist(self.minerva_core)
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.params
                
                if request['input_type'] == 'file':
                    results = watch.add_watchlist_file(request)
                else:
                    results = watch.add_watchlist(request)
               
                return '<script type="text/javascript">window.alert("%s"); location="/watchlist";</script>' % results

            else:
                context_dict = {}
                context_dict['form'] = 'watchlist'
                numFound, items_found = watch.get_watchlist()
                context_dict['numFound'] = numFound
                context_dict['items_found'] = items_found
                context_dict['permissions'] = perm_return
                context_dict['sizeLimit'] = self.sizeLimit
                tmp = env.get_template('watchlist.jinja')
                return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.params

            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)
                 

    '''Start of Post only Functions'''
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def close_nc(self, **kwargs):
        if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session ) or cherrypy.request.method == 'POST':
            user = Users(self.minerva_core)
            cherrypy.session['prev_page'] = "/close_nc"
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')
                
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            
            if 'PasswordReset' in perm_return:
                if cherrypy.request.method == 'POST':
                    cherrypy.session['post_request'] = cherrypy.request.json

                raise cherrypy.HTTPRedirect('/profile')

            elif 'console' in perm_return or 'responder' in perm_return:
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json                

                alerts = alert_console(self.minerva_core)
                alerts.close_alert_nc(request['events'])
                
                if request['formType'] == "investigate":
                    return '<script type="text/javascript">window.close()</script>'

                elif request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')

                elif request['formType'] == 'responder':
                    raise cherrypy.HTTPRedirect('/responder')

                elif request['formType'] == 'alerts':
                    raise cherrypy.HTTPRedirect('/alerts')

            elif 'newLogin' in perm_return:
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')

            else:
                raise cherrypy.HTTPError(403)

        else:
                raise cherrypy.HTTPError(404)
    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def close(self, **kwargs):
        if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session):
            user = Users(self.minerva_core)
            cherrypy.session['prev_page'] = '/close'
            
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')
                
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            
            if 'PasswordReset' in perm_return:
                if cherrypy.request.method == 'POST':
                    cherrypy.session['post_request'] = cherrypy.request.json
    
                raise cherrypy.HTTPRedirect('/profile')
    
            elif 'console' in perm_return or 'responder' in perm_return:
                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json
                alerts = alert_console(self.minerva_core)
                username = user.get_username(cherrypy.session.get('SESSION_KEY'))
                alerts.close_alert(request['events'], request['comments'], username)
                
                if request['formType'] == "investigate":
                    return '<script type="text/javascript">window.close()</script>'
                elif request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')
                elif request['formType'] == 'responder':
                    raise cherrypy.HTTPRedirect('/responder')
                elif request['formType'] == 'alerts':
                    raise cherrypy.HTTPRedirect('/alerts')
            elif 'newLogin' in perm_return:
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')
            else:
                raise cherrypy.HTTPError(403)
        else:
            raise cherrypy.HTTPError(404)
            
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def escalate(self, **kwargs):
        if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session):
            user = Users(self.minerva_core)
            cherrypy.session['prev_page'] = '/escalate'
            
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')
            
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            
            if 'PasswordReset' in perm_return:
                if cherrypy.request.method == 'POST':
                    cherrypy.session['post_request'] = cherrypy.request.json

                raise cherrypy.HTTPRedirect('/profile')

            elif 'console' in perm_return:                
                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json

                username = user.get_username(cherrypy.session.get('SESSION_KEY'))
                alerts = alert_console(self.minerva_core)
                alerts.escalate_alert(request['events'], request['comments'], username)
                
                if request['formType'] == "investigate":
                    return '<script type="text/javascript">window.close()</script>'

                elif request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')

                elif request['formType'] == 'responder':
                    raise cherrypy.HTTPRedirect('/responder')

                elif request['formType'] == 'alerts':
                    raise cherrypy.HTTPRedirect('/alerts')

            elif 'newLogin' in perm_return:
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')

            else:
                raise cherrypy.HTTPError(403)

        else:
            raise cherrypy.HTTPError(404)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def comment(self, **kwargs):
        if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session):
            user = Users(self.minerva_core)
            cherrypy.session['prev_page'] = '/comment'

            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')

            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

            if 'PasswordReset' in perm_return:
                if cherrypy.request.method == 'POST':
                    cherrypy.session['post_request'] = cherrypy.request.json

                raise cherrypy.HTTPRedirect('/profile')

            elif 'console' in perm_return or 'responder' in perm_return:
                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json

                alerts = alert_console(self.minerva_core)
                username = user.get_username(cherrypy.session.get('SESSION_KEY'))
                alerts.add_comments(request['events'], request['comments'], username)

                if request['formType'] == "investigate":
                    return '<script type="text/javascript">window.close()</script>'

                if request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')

                elif request['formType'] == 'responder':
                    raise cherrypy.HTTPRedirect('/responder')

                elif request['formType'] == 'alerts':
                    raise cherrypy.HTTPRedirect('/alerts')

            elif 'newLogin' in perm_return:
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')

            else:
                raise cherrypy.HTTPError(403)

        else:
            raise cherrypy.HTTPError(404)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def watchlist_json(self, **kwargs):
        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = "/watchlist_json"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'event_filters' in perm_return:
            watch = watchlist(self.minerva_core)
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json

                results = watch.change_watchlist(request)

                return '%s' % results
            else:
                raise cherrypy.HTTPError(404)

        elif 'newLogin' in perm_return:
            cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)

    '''Functions for retreiving and downloading PCAP'''
    def download_complete(self):
        tmp_file = cherrypy.session['pcap_file']
        del cherrypy.session['pcap_file']
        tmp_file.close()
    

    @cherrypy.expose
    def download(self, **kwargs):
        if 'pcap_file' in cherrypy.session.keys():
            cherrypy.request.hooks.attach('on_end_request', self.download_complete)
            return cherrypy.lib.static.serve_download(cherrypy.session['pcap_file'].name)

        else:
            return '<script>window.close();</script>'


    @cherrypy.expose
    @cherrypy.tools.json_in()
    def get_pcap(self, **kwargs):
        user = Users(self.minerva_core)

        if not 'SESSION_KEY' in cherrypy.session.keys():
            cherrypy.session['prev_page'] = '/get_pcap'
            cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
        
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        
        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'console' in perm_return or 'responder' in perm_return:
            if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session):
                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']

                else:
                    request = cherrypy.request.json

                pcaps = HandleRequests(self.minerva_core)

                #todo, zip up multiple file and return that
                if request['formType'] == 'flow':
                    pcap = pcaps.flowPCAP(request['events'])

                else:
                    pcap = pcaps.alertPCAP(request['events'])

                if isinstance(pcap, basestring):
                    return '<script type="text/javascript">window.alert("%s");window.close();</script>' % pcap

                else:
                    tmp = NamedTemporaryFile(mode='w+b', suffix='.pcap')
                    tmp.write(pcap.read())
                    tmp.flush()
                    cherrypy.session['pcap_file'] = tmp
                    return '<script type="text/javascript">location="/download";</script>'

            else:
                raise cherrypy.HTTPError(404)

        elif 'newLogin' in perm_return:
            cherrypy.session['prev_page'] = '/get_pcap'
            cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)
    
    # NEW STUFF HERE
    @cherrypy.expose
    def ws(self):
        user = Users(self.minerva_core)

        if not 'SESSION_KEY' in cherrypy.session.keys():
            cherrypy.session['prev_page'] = '/get_pcap'
            cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPError(403)

        else:
            cherrypy.request.ws_handler.session_id = cherrypy.session['SESSION_KEY']
            cherrypy.log("Handler created: {}".format(repr(cherrypy.request.ws_handler)))


    @cherrypy.expose
    def index(self, **kwargs):
        user = Users(self.minerva_core)
        cherrypy.session['prev_page'] = "/"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            raise cherrypy.HTTPRedirect('/login')

        perm_return =  user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'PasswordReset' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json

            raise cherrypy.HTTPRedirect('/profile')

        elif 'console' in perm_return:
            context_dict = {}
            alerts = alert_console(self.minerva_core)
            context_dict['results'] = []
            context_dict['sizeLimit'] = self.sizeLimit
            context_dict['form'] = 'console'
            context_dict['title'] = 'Alert'
            context_dict['permissions'] = perm_return
            context_dict['session_id'] = cherrypy.session.get('SESSION_KEY')
            tmp = env.get_template('console.jinja')
            return tmp.render(context_dict)

        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')

        else:
            raise cherrypy.HTTPError(403)



'''Startup functions'''
def genKey(cur_config, minerva_core):
    if not os.path.exists(os.path.dirname(cur_config['certs']['webserver_cert'])):
        os.makedirs(os.path.dirname(cur_config['certs']['webserver_cert']))
    if not os.path.exists(os.path.dirname(cur_config['certs']['webserver_key'])):
        os.makedirs(os.path.dirname(cur_config['certs']['webserver_key']))
    cmd = [ 
        'openssl', 
        'req', 
        '-x509', 
        '-newkey', 
        'rsa:2048', 
        '-keyout', 
        cur_config['certs']['webserver_key'], 
        '-out', 
        cur_config['certs']['webserver_cert'], 
        '-days', 
        '3650', 
        '-nodes', 
        '-batch', 
        '-subj', 
        '/CN={}'.format(cur_config['hostname'])
    ]
    subprocess.call(cmd)

def checkCert(cur_config, minerva_core):
    db = minerva_core.get_db()
    certdb = db.certs
    results = certdb.find_one({"type": "webserver"})
    if not results:
        certdb.insert({
            "SERVER": "webserver", 
            "type": "webserver", 
            "CERT": open(cur_config['certs']['webserver_cert'],'r').read(), 
            "key": open(cur_config['certs']['webserver_key'],'r').read(),
            "STATUS": "APPROVED" 
        } )
    else:
        cert = results['CERT']
        if cert != open(cur_config['certs']['webserver_cert'],'r').read():
            certdb.update({"SERVER": "webserver"},{ 
                "$set": { 
                    "CERT": open(cur_config['certs']['webserver_cert'],'r').read(),
                    "key":  open(cur_config['certs']['webserver_key'],'r').read()
            }})
    return


def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    headers['Content-Security-Policy'] = "default-src='self'"
    headers['Strict-Transport-Security'] = 'max-age=3600'

def handleError():
    cherrypy.response.status = 500
    cherrypy.response.body = [open(os.path.join(os.path.dirname(sys.argv[0]),'static','html','500.html'),'r').read()]

if __name__ == '__main__':
    #minerva_core = core.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml'))
    minerva_core = core.MinervaConfigs()
    server_config = minerva_core.conf['Webserver']['web']
    if not os.path.exists(server_config['certs']['webserver_cert']) or not os.path.exists(server_config['certs']['webserver_cert']):
        genKey(server_config, minerva_core)
    checkCert(server_config, minerva_core)
    if 'port' not in server_config:
        port = 443
    else:
        port = server_config['port']
        
    cherrypy.tools.secureheaders = cherrypy.Tool('before_finalize', secureheaders, priority=60)
    cherrypy.config.update({'server.socket_host': server_config['bindIp'],
                            'server.socket_port': port,
                            'server.ssl_certificate': server_config['certs']['webserver_cert'],
                            'server.ssl_private_key': server_config['certs']['webserver_key'],
                            'server.ssl_module': 'builtin',
                            'tools.secureheaders.on': True,
                            'tools.sessions.secure': True,
                            'tools.sessions.httponly': True,
                            'tools.sessions.on': True,
                            'tools.sessions.timeout': int(server_config['session_timeout']),
                            'server.thread_pool': int(server_config['threads']),
                            'server.thread_pool_max': int(server_config['threads']),
                            'error_page.404': os.path.join(os.path.dirname(sys.argv[0]),'static','html','404.html'),
                            'error_page.403': os.path.join(os.path.dirname(sys.argv[0]),'static','html','403.html'),
                            'request.error_response': handleError,
                          })
    base_dir = os.path.abspath(os.path.dirname(sys.argv[0]))

    #TODO
    MinervaPlugin(cherrypy.engine, minerva_core).subscribe()
    #MinervaEventPlugin(cherrypy.engine).subscribe()
    cherrypy.tools.websocket = WebSocketTool()


    config = {
        '/ws' : {
            'tools.websocket.on': True,
            'tools.websocket.handler_cls': MinervaWebSocketHandler, #TODO
        },
        '/css': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(base_dir,'static','css'),
            },
        '/js': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(base_dir,'static','js'),
        },
        '/jquery.min.js': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename': os.path.join(base_dir,'static','jquery','jquery.min.js'),
        },
        '/images': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(base_dir,'static','images'),
        },
        '/fonts': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(base_dir,'static','fonts'),
        },
    }
    cherrypy.quickstart(Webserver(minerva_core), config = config)
