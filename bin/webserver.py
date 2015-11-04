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

import cherrypy
from jinja2 import Environment, FileSystemLoader
from Minerva import core
from Minerva.server import alert_console, alert_flow, sensors, Users, iso_to_utc, epoch_to_datetime, HandleRequests
import os
import time
import platform
import subprocess
import shutil
import sys
from tempfile import NamedTemporaryFile
env = Environment(loader=FileSystemLoader('templates'))
env.filters['iso_to_utc'] = iso_to_utc
env.filters['epoch_to_datetime'] = epoch_to_datetime

class Minerva(object):
    def __init__(self, minerva_core):
        #minerva_core = core.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml'))
        self.configs = minerva_core.conf['Webserver']
        self.sizeLimit = self.configs['events']['maxResults']
        self.minerva_core = minerva_core
    
    @cherrypy.expose
    def login(self, **kwargs):
        authUser = Users(self.configs)
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
                else:
                    raise cherrypy.HTTPError("403 Forbidden", "You are not allowed to access this resource.")
            else:
                return '<script type="text/javascript">window.alert("Invalid Username or Pasword");location="/login";</script>'
        else:
            tmp = env.get_template('login.html')
            return tmp.render()
    
    @cherrypy.expose
    def logout(self, **kwargs):
        if 'SESSION_KEY' in cherrypy.session.keys():
            del cherrypy.session['SESSION_KEY']
        raise cherrypy.HTTPRedirect("/")
    
    @cherrypy.expose
    def users(self, **kwargs):
        users = Users(self.configs)
        cherrypy.session['prev_page'] = "/users"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
        perm_return =  users.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'user_admin' in perm_return:
            retstatus = 'None'
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
               if 'post_request' in cherrypy.session.keys():
                   request = cherrypy.session['post_request'] 
                   del cherrypy.session['post_request']
               else:
                   request = cherrypy.request.params
               if request['updateType'] == 'new_user':
                   retstatus = users.create_user(request['username'], request['password'], request['console'], request['responder'], request['sensor_admin'], request['user_admin'], request['server_admin'], request['enabled'])
               elif request['updateType'] == 'updateUser':
                   retstatus = users.modify_user(request['username'], request['password'], request['console'], request['responder'], request['sensor_admin'], request['user_admin'], request['server_admin'], request['enabled'])
               elif request['updateType'] == 'updatePerms':
                   retstatus = users.changePerms(request['username'], request['console'], request['responder'], request['sensor_admin'], request['user_admin'], request['server_admin'], request['enabled'])
            if retstatus == "Password Check Failed":
                ret_string = '<script type="text/javascript">window.alert("New Password does not meet strength Requirements: %s lowercase, %s uppercase, %s numbers, %s special characters");location="/users";</script>' % ( self.configs['web']['password_requirements']['lower_count'], self.configs['web']['password_requirements']['upper_count'], self.configs['web']['password_requirements']['digit_count'], self.configs['web']['password_requirements']['special_count'] )
                return ret_string
            elif retstatus != "None":
                return_msg =  '<script type="text/javascript">window.alert("%s");location="/users";</script>' % retstatus
                return return_msg
            context_dict = {}
            context_dict['items_found'] = users.getAllUsers()
            context_dict['form'] = 'usermanagement'
            context_dict['ReturnStatus'] = retstatus 
            context_dict['permissions'] = perm_return
            tmp = env.get_template('users.html')
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not authorized to access this resource")
        return tmp.render(context_dict)
    
    @cherrypy.expose
    def index(self, **kwargs):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = "/"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            raise cherrypy.HTTPRedirect('/login')
        perm_return =  user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'console' in perm_return:
            context_dict = {}
            alerts = alert_console(self.configs)
            numFound, items_found = alerts.get_alerts()
            context_dict['numFound'] = numFound
            context_dict['items_found'] = items_found
            context_dict['sizeLimit'] = self.sizeLimit
            context_dict['form'] = 'console'
            context_dict['title'] = 'Alert'
            context_dict['permissions'] = perm_return
            tmp = env.get_template('console.html')
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not authorized to access this resource.")
    
    @cherrypy.expose
    def profile(self, **kwargs):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = "/profile"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            raise cherrypy.HTTPRedirect('/login')
        if cherrypy.request.method == 'POST':
            request = cherrypy.request.params
            if request['newPassword'] != request['newPassword2']:
                return '<script type="text/javascript">window.alert("New Passwords do not match");location="/profile";</script>'
            ret_status = user.changePW(cherrypy.session['SESSION_KEY'], request['currentPW'], request['newPassword'])
            if ret_status == 'success':
                return '<script type="text/javascript">window.alert("Password Successfully Changed");location="/profile";</script>'
            elif ret_status == 'badOldPass':
                return '<script type="text/javascript">window.alert("Current Password is incorrect");location="/profile";</script>'
            elif ret_status == 'newLogin':
                return '<script type="text/javascript">window.alert("Session Expired, Please log in with Previous Password");location="/login";</script>'
            #elif ret_status == "Password is too short":
                #return '<script type="text/javascript">window.alert("New Password is too short");location="/profile";</script>'
            elif ret_status == "Password Check Failed":
                ret_string = '<script type="text/javascript">window.alert("New Password does not meet strength Requirements: %s lowercase, %s uppercase, %s numbers, %s special characters");location="/profile";</script>' % ( self.configs['web']['password_requirements']['lower_count'], self.configs['web']['password_requirements']['upper_count'], self.configs['web']['password_requirements']['digit_count'], self.configs['web']['password_requirements']['special_count'] )
                return ret_string
        else:
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            if 'newLogin' in perm_return:
                raise cherrypy.HTTPRedirect('/login')
            else:
                context_dict = {}
                context_dict['form'] = 'profile'
                context_dict['permissions'] = perm_return
                tmp = env.get_template('profile.html')
                return tmp.render(context_dict)
                 
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def close_nc(self, **kwargs):
        if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session ) or cherrypy.request.method == 'POST':
            user = Users(self.configs)
            cherrypy.session['prev_page'] = "/close_nc"
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')
                
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            
            if 'console' in perm_return or 'responder' in perm_return:
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json                
                alerts = alert_console(self.configs)
                alerts.close_alert_nc(request['events'])
                
                if request['formType'] == "AlertFlow":
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
                raise cherrypy.HTTPError("403 Forbidden", "You are not authorized to access this resource.")
        else:
                raise cherrypy.HTTPError(404)
    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def close(self, **kwargs):
        if cherrypy.request.method == 'POST' or (cherrypy.session.method == 'GET' and 'post_request' in cherrypy.session):
            user = Users(self.configs)
            cherrypy.session['prev_page'] = '/close'
            
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')
                
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            
            if 'console' in perm_return or 'responder' in perm_return:
                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json
                alerts = alert_console(self.configs)
                alerts.close_alert(request['events'], request['comments'])
                
                if request['formType'] == "AlertFlow":
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
                raise cherrypy.HTTPError("403 Forbidden", "You are not authorized to access this resource")
        else:
            raise cherrypy.HTTPError(404)
            
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def escalate(self, **kwargs):
        if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session):
            user = Users(self.configs)
            cherrypy.session['prev_page'] = '/escalate'
            
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['post_request'] = cherrypy.request.json
                raise cherrypy.HTTPRedirect('/login')
            
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            
            if 'console' in perm_return:                
                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json
                alerts = alert_console(self.configs)
                alerts.escalate_alert(request['events'], request['comments'])
                
                if request['formType'] == "AlertFlow":
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
                raise cherrypy.HTTPError("403 Forbidden", "You are not authorized to access this resource")
        else:
            raise cherrypy.HTTPError(404)
            
    @cherrypy.expose
    def responder(self):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = "/responder"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            raise cherrypy.HTTPRedirect('/login')
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'responder' in perm_return:
            context_dict = {}
            alerts = alert_console(self.configs)
            numFound, items_found = alerts.get_escalated_alerts()
            context_dict['numFound'] = numFound
            context_dict['items_found'] = items_found
            context_dict['sizeLimit'] = self.sizeLimit
            context_dict['form'] = 'responder'
            context_dict['title'] = 'Escalation'
            context_dict['permissions'] = perm_return
            tmp = env.get_template('console.html')
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def flow(self, **kwargs):
        user = Users(self.configs)
   
        if 'prev_page' in cherrypy.session and 'orig_search' in cherrypy.session:
            if cherrypy.session['prev_page'] == '/flow' and not 'get_request' in cherrypy.session:
                del cherrypy.session['orig_search']

        cherrypy.session['prev_page'] = "/flow"

        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')

        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))

        if 'console' in perm_return or 'responder' in perm_return:
            context_dict = {'numFound': 0}

            if (cherrypy.request.method == 'GET' and ('orig_search' in cherrypy.session.keys() or 'post_request' in cherrypy.session.keys())) or cherrypy.request.method == 'POST':

                flow = alert_flow(self.configs)

                if 'orig_search' in cherrypy.session:
                    request = cherrypy.session['orig_search']
                    del cherrypy.session['orig_search']
                    items_found, orig_search = flow.search_flow(request, orig_search=True)
                else:
                    if 'post_request' in cherrypy.session.keys():
                        request = cherrypy.session['post_request']
                        del cherrypy.session['post_request']
                    else:
                        request = cherrypy.request.json

                    items_found, orig_search = flow.search_flow(request)

                context_dict['items_found'] = list(items_found)
                context_dict['numFount'] = len(context_dict['items_found'])
                context_dict['orig_search'] = orig_search
                cherrypy.session['orig_search'] = orig_search

            context_dict['form'] = 'flow'
            context_dict['permissions'] = perm_return
            context_dict['sizeLimit'] = self.sizeLimit
            tmp = env.get_template('flow.html')
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['port_request'] = cherrypy.request.json
            raise cheryypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
            
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def alerts(self, **kwargs):
        user = Users(self.configs)
        
        if 'prev_page' in cherrypy.session and 'orig_search' in cherrypy.session:
            if cherrypy.session['prev_page'] == '/alerts' and not 'get_request' in cherrypy.session:
                del cherrypy.session['orig_search']

        cherrypy.session['prev_page'] = '/alerts'
        
        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['get_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
            
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        
        if 'console' in perm_return or 'responder' in perm_return:
            context_dict = { 'numFound': 0 }
            
            if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and ('get_request' in cherrypy.session or 'orig_search' in cherrypy.session)):
                alert = alert_console(self.configs)
                if 'orig_search' in cherrypy.session:
                    request = cherrypy.session['orig_search']
                    del cherrypy.session['orig_search']
                    items_found, orig_search = alert.search_alerts(request, orig_search=True)
                else:
                    if 'get_request' in cherrypy.session.keys():
                        request = cherrypy.session['get_request']
                        del cherrypy.session['get_request']
                    else:
                        request = cherrypy.request.json
                
                    items_found, orig_search = alert.search_alerts(request)

                context_dict['items_found'] = list(items_found)
                context_dict['numFound'] = len(context_dict['items_found'])
                context_dict['orig_search'] = orig_search
                cherrypy.session['orig_search'] = orig_search
                
            context_dict['form'] = 'alerts'
            context_dict['permissions'] = perm_return
            context_dict['sizeLimit'] = self.sizeLimit
            tmp = env.get_template('alerts.html')            
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            cherrypy.session['get_request'] = cherrypy.request.params
            raise cheryypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
            
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
        user = Users(self.configs)

        if not 'SESSION_KEY' in cherrypy.session.keys():
            cherrypy.session['prev_page'] = '/get_pcap'
            cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
        
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        
        if 'console' in perm_return or 'responder' in perm_return:
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
                if pcap == 'No Packets Found':
                    return '<script type="text/javascript">window.alert("No Packets Found");window.close();</script>'
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
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def comment(self, **kwargs):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = '/comment'
        
        if not 'SESSION_KEY' in cherrypy.session.keys():
            cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
            
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        
        if 'console' in perm_return or 'responder' in perm_return:
            if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session):
                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json
                alerts = alert_console(self.configs)
                alerts.add_comments(request['events'], request['comments'])
                
                if request['formType'] == "AlertFlow":
                    return '<script type="text/javascript">window.close()</script>'
                if request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')
                elif request['formType'] == 'responder':
                    raise cherrypy.HTTPRedirect('/responder')
                elif request['formType'] == 'alerts':
                    raise cherrypy.HTTPRedirect('/alerts')
            else:
                raise cherrypy.HTTPError(404)
        elif 'newLogin' in perm_return:
            cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
            
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def get_alert_flow(self, **kwargs):
        user = Users(self.configs)
        
        if not 'SESSION_KEY' in cherrypy.session.keys():
           cherrypy.session['prev_page'] = '/get_alert_flow'
           cherrypy.session['post_request'] = cherrypy.request.json
           raise cherrypy.HTTPRedirect('/login')
           
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        
        if 'console' in perm_return or 'responder' in perm_return:
            if cherrypy.request.method == 'POST' or (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session):
                flow = alert_flow(self.configs)
                if 'post_request' in cherrypy.session:
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json

                items = flow.get_flow(request['events'])
                
                context_dict = {}
                context_dict['items'] = items
                context_dict['form'] = request['formType']
                
                tmp = env.get_template('alert_flow.html')
                return tmp.render(context_dict)
            else:
                raise cherrypy.HTTPError(404)
        elif 'newLogin' in perm_return:
            cherrypy.session['prev_page'] = 'get_alert_flow'
            cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
    
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def config(self, **kwargs):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = "/config"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'server_admin' in perm_return:
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_reqeust' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json
                server_config = core.MinervaConfigs()
                new_config = server_config.parse_web_configs(request)
                out_tmp = env.get_template('minerva.yaml')
                shutil.copy(os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml'),os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml.bkup'))
                out_yaml = open(os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml'), 'w')
                out_yaml.write(out_tmp.render({"config": new_config}))
                out_yaml.close()
                return_msg =  '<script type="text/javascript">window.alert("Changes Saved.  A restart is required to take full effect");location="/config";</script>'
                return return_msg
            else:
                context_dict = {}
                context_dict['config'] = self.configs
                context_dict['form'] = 'server_admin'
                context_dict['permissions'] = perm_return
                tmp = env.get_template('config.html')
                return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError('403 Forbidden', "You are not permitted to access this resource")
            
    @cherrypy.expose
    @cherrypy.tools.json_in()
    def sensors(self, **kwargs):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = "/sensors"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.json
            raise cherrypy.HTTPRedirect('/login')
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'sensor_admin' in perm_return:
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.json
                sensor = sensors(self.configs)
                sensor.update(request['sensors'],request['action'])
            context_dict = {}
            sensor = sensors(self.configs)
            items_found = sensor.get_sensors()
            context_dict['items_found'] = items_found
            context_dict['form'] = 'sensors'
            context_dict['permissions'] = perm_return
            tmp = env.get_template('sensors.html')
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")

def genKey(cur_config, minerva_core):
    if not os.path.exists(os.path.dirname(cur_config['certs']['webserver_cert'])):
        os.makedirs(os.path.dirname(cur_config['certs']['webserver_cert']))
    if not os.path.exists(os.path.dirname(cur_config['certs']['webserver_key'])):
        os.makedirs(os.path.dirname(cur_config['certs']['webserver_key']))
    cmd = [ 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', cur_config['certs']['webserver_key'], '-out', cur_config['certs']['webserver_cert'], '-days', '3650', '-nodes', '-batch', '-subj', '/CN=%s' % cur_config['hostname']]
    subprocess.call(cmd)
    db = minerva_core.get_db()
    certdb = db.certs
    results = list(certdb.find({"type": "webserver"}))
    if len(results) > 0:
        certdb.update({"type": "webserver"},{ "$set": { "cert": open(cur_config['certs']['webserver_cert'],'r').read() }})
    else:
        certdb.insert({"type": "webserver", "cert": open(cur_config['certs']['webserver_cert'],'r').read() } )

def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    headers['Content-Security-Policy'] = "default-src='self'"
    headers['Strict-Transport-Security'] = 'max-age=3600'

if __name__ == '__main__':
    minerva_core = core.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml'))
    server_config = minerva_core.conf['Webserver']['web']
    if not os.path.exists(server_config['certs']['webserver_cert']) or not os.path.exists(server_config['certs']['webserver_cert']):
        genKey(server_config, minerva_core)
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
                          })
    config = {
        '/css': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.getcwd(), 'static/css'),
            },
        '/js': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.getcwd(), 'static/js'),
        },
        '/jquery.min.js': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename': os.path.join(os.getcwd(), 'static/jquery/jquery.min.js'),
        },
        '/images': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.getcwd(), 'static/images'),
        },
        '/fonts': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(os.getcwd(), 'static/fonts'),
        },
    }
    cherrypy.quickstart(Minerva(minerva_core), config = config)
