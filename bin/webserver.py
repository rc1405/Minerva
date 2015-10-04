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

from Minerva.server.alerts import alert_console
from Minerva.server.flows import alert_flow
from Minerva.server.sensors import sensors
from Minerva.server.users import Users
import cherrypy
from jinja2 import Environment, FileSystemLoader
from Minerva.server.date_filters import iso_to_utc
from Minerva import core
import os
import M2Crypto
import time
import platform
import subprocess
env = Environment(loader=FileSystemLoader('templates'))
env.filters['iso_to_utc'] = iso_to_utc

class Minerva(object):
    def __init__(self):
        self.configs = core.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')).conf['Webserver']
        self.sizeLimit = self.configs['events']['maxResults']
    @cherrypy.expose
    def favicon(self):
        return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/favicon.ico'), content_type="image/x-icon")
    @cherrypy.expose
    def bootstrap_min_css(self):
        return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/bootstrap/css/bootstrap.min.css'), content_type="text/css")
    @cherrypy.expose
    def bootstrap_theme_min_css(self):
        return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/bootstrap/css/bootstrap-theme.min.css'), content_type="text/css")
    @cherrypy.expose
    def bootstrap_min_js(self):
        return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/bootstrap/js/bootstrap.min.js'), content_type="application/javascript")
    @cherrypy.expose
    def bootstrap_signin_css(self):
        return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/bootstrap/css/signin.css'), content_type="text/css")
    @cherrypy.expose
    def jquery_min_js(self):
        return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/jquery/jquery.min.js'), content_type="application/javascript")
    @cherrypy.expose
    def arrow(self):
        return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/arrow.png'), content_type="image/png")
    #@cherrypy.expose
    #def bootstrap_datetime_css(self):
        #return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/bootstrap/css/bootstrap-datetimepicker.min.css'), content_type="text/css")
    #@cherrypy.expose
    #def bootstrap_datetime_js(self):
        #return cherrypy.lib.static.serve_file(os.path.join(os.getcwd(),'static/bootstrap/js/bootstrap-datetimepicker.min.js'), content_type="application/javascript")
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
                cherrypy.session['post_request'] = cherrypy.request.params
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
            if retstatus != "None":
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
            elif ret_status == "Password is too short":
                return '<script type="text/javascript">window.alert("New Password is too short");location="/profile";</script>'
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
    def close_nc(self, **kwargs):
        if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session) or cherrypy.request.method == 'POST':
            user = Users(self.configs)
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['prev_page'] = "/close_nc"
                cherrypy.session['post_request'] = cherrypy.request.params
                raise cherrypy.HTTPRedirect('/login')
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            if 'console' in perm_return or 'responder' in perm_return:
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.params
                alerts = alert_console(self.configs)
                alerts.close_alert_nc(request['events'])
                if request['formType'] == "AlertFlow":
                    return '<script type="text/javascript">window.close()</script>'
                elif request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')
                else:
                    raise cherrypy.HTTPRedirect('/responder')
            elif 'newLogin' in perm_return:
                cherrypy.session['prev_page'] = "/close_nc"
                cherrypy.session['post_request'] = cherrypy.request.params
                raise cherrypy.HTTPRedirect('/login')
            else:
                raise cherrypy.HTTPError("403 Forbidden", "You are not authorized to access this resource.")
        else:
                raise cherrypy.HTTPError(404)
    @cherrypy.expose
    def close(self, **kwargs):
        if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session) or cherrypy.request.method == 'POST':
            user = Users(self.configs)
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['prev_page'] = '/close'
                cherrypy.session['post_request'] = cherrypy.request.params
                raise cherrypy.HTTPRedirect('/login')
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            if 'console' in perm_return or 'responder' in perm_return:
                alerts = alert_console(self.configs)
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.params
                alerts.close_alert(request['events'], request['comments'])
	        if request['formType'] == "AlertFlow":
                    return '<script type="text/javascript">window.close()</script>'
                elif request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')
                else:
                    raise cherrypy.HTTPRedirect('/responder')
            elif 'newLogin' in perm_return:
                cherrypy.session['prev_page'] = '/close'
                cherrypy.session['post_request'] = cherrypy.request.params
                raise cherrypy.HTTPRedirect('/login')
            else:
                raise cherrypy.HTTPError("403 Forbidden", "You are not authorized to access this resource")
        else:
            raise cherrypy.HTTPError(404)
    @cherrypy.expose
    def escalate(self, **kwargs):
        if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session) or cherrypy.request.method == 'POST':
            user = Users(self.configs)
            if not 'SESSION_KEY' in cherrypy.session.keys():
                cherrypy.session['prev_page'] = '/escalate'
                cherrypy.session['post_request'] = cherrypy.request.params
                raise cherrypy.HTTPRedirect('/login')
            perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
            if 'console' in perm_return:
                alerts = alert_console(self.configs)
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.params
                alerts.escalate_alert(request['events'], request['comments'])
                if request['formType'] == "AlertFlow":
                    return '<script type="text/javascript">window.close()</script>'
                elif request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')
                else:
                    raise cherrypy.HTTPRedirect('/responder')
            elif 'newLogin' in perm_return:
                cherrypy.session['prev_page'] = '/escalate'
                cherrypy.session['post_request'] = cherrypy.request.params
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
            context_dict['permissions'] = perm_return
            tmp = env.get_template('console.html')
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
    @cherrypy.expose
    def flow(self, **kwargs):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = "/flow"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.params
            raise cherrypy.HTTPRedirect('/login')
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'console' in perm_return or 'responder' in perm_return:
            context_dict = {}
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.params
                flow = alert_flow(self.configs)
                context_dict['items_found'] = flow.search_flow(request)
            context_dict['form'] = 'flow'
            context_dict['permissions'] = perm_return
            context_dict['sizeLimie'] = self.sizeLimit
            tmp = env.get_template('flow.html')
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['port_request'] = cherrypy.request.params
            raise cheryypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
    @cherrypy.expose
    def comment(self, **kwargs):
        user = Users(self.configs)
        if not 'SESSION_KEY' in cherrypy.session.keys():
            cherrypy.session['prev_page'] = '/comment'
            cherrypy.session['post_request'] = cherrypy.request.params
            raise cherrypy.HTTPRedirect('/login')
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'console' in perm_return or 'responder' in perm_return:
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                alerts = alert_console(self.configs)
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.params
                alerts.add_comments(request['events'], request['comments'])
                if request['formType'] == "AlertFlow":
                    return '<script type="text/javascript">window.close()</script>'
                if request['formType'] == 'console':
                    raise cherrypy.HTTPRedirect('/')
                else:
                    raise cherrypy.HTTPRedirect('/responder')
            else:
                raise cherrypy.HTTPError(404)
        elif 'newLogin' in perm_return:
            cherrypy.session['prev_page'] = '/comment'
            cherrypy.session['post_request'] = cherrypy.request.params
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
    @cherrypy.expose
    def get_alert_flow(self, **kwargs):
        user = Users(self.configs)
        if not 'SESSION_KEY' in cherrypy.session.keys():
           cherrypy.session['prev_page'] = '/get_alert_flow'
           cherrypy.session['post_request'] = cherrypy.request.params
           raise cherrypy.HTTPRedirect('/login')
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'console' in perm_return or 'responder' in perm_return:
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.params
                context_dict = {}
                flow = alert_flow(self.configs)
                items_found, orig_alert = flow.get_flow(request['ID'])
                context_dict['items_found'] = items_found
                context_dict['orig_alert'] = orig_alert
                context_dict['form'] = request['formType']
                context_dict['alert_id'] = request['ID']
                tmp = env.get_template('alert_flow.html')
                return tmp.render(context_dict)
            else:
                raise cherrypy.HTTPError(404)
        elif 'newLogin' in perm_return:
            cherrypy.session['prev_page'] = 'get_alert_flow'
            cherrypy.session['post_request'] = cherrypy.request.params
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError("403 Forbidden", "You are not permitted to access this resource")
    @cherrypy.expose
    def config(self, **kwargs):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = "/config"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.params
            raise cherrypy.HTTPRedirect('/login')
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'server_admin' in perm_return:
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_reqeust' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrypy.session['post_request']
                else:
                    request = cherrypy.request.params
                server_config = core.MinervaConfigs()
                new_config = server_config.parse_web_configs(request)
                out_tmp = env.get_template('minerva.yaml')
                out_yaml = open('/tmp/blah.yaml','w')
                out_yaml.write(out_tmp.render({"config": new_config}))
                out_yaml.close()
            context_dict = {}
            context_dict['config'] = self.configs
            context_dict['form'] = 'server_admin'
            context_dict['permissions'] = perm_return
            tmp = env.get_template('config.html')
            return tmp.render(context_dict)
        elif 'newLogin' in perm_return:
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.params
            raise cherrypy.HTTPRedirect('/login')
        else:
            raise cherrypy.HTTPError('403 Forbidden', "You are not permitted to access this resource")
            
    @cherrypy.expose
    def sensors(self, **kwargs):
        user = Users(self.configs)
        cherrypy.session['prev_page'] = "/sensors"
        if not 'SESSION_KEY' in cherrypy.session.keys():
            if cherrypy.request.method == 'POST':
                cherrypy.session['post_request'] = cherrypy.request.params
            raise cherrypy.HTTPRedirect('/login')
        perm_return = user.get_permissions(cherrypy.session.get('SESSION_KEY'))
        if 'sensor_admin' in perm_return:
            if (cherrypy.request.method == 'GET' and 'post_request' in cherrypy.session.keys()) or cherrypy.request.method == 'POST':
                if 'post_request' in cherrypy.session.keys():
                    request = cherrypy.session['post_request']
                    del cherrpy.session['post_request']
                else:
                    request = cherrypy.request.params
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
def genKey(cur_config):
    if not os.path.exists(os.path.dirname(cur_config['certs']['webserver_cert'])):
        os.makedirs(os.path.dirname(cur_config['certs']['webserver_cert']))
    if not os.path.exists(os.path.dirname(cur_config['certs']['webserver_key'])):
        os.makedirs(os.path.dirname(cur_config['certs']['webserver_key']))
    cmd = [ 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-keyout', cur_config['certs']['webserver_key'], '-out', cur_config['certs']['webserver_cert'], '-days', '3650', '-nodes', '-batch']
    subprocess.call(cmd)
    #key = M2Crypto.RSA.gen_key(2048, 65537)
    #key.save_pub_key(cur_config['client_public'])
    #key.save_key(cur_config['certs']['webserver_key'], cipher=None)
    #pkey = M2Crypto.EVP.PKey()
    #pkey.assign_rsa(key)
    #cur_time = M2Crypto.ASN1.ASN1_UTCTIME()
    #cur_time.set_time(int(time.time()) - 60*60*24)
    #expire_time = M2Crypto.ASN1.ASN1_UTCTIME()
    #expire_time.set_time(int(time.time()) + 60*60*24*365*10)
    #cert = M2Crypto.X509.X509()
    #cert.set_pubkey(pkey)
    #cs_name = M2Crypto.X509.X509_Name()
    #cs_name.C = 'US'
    ##cs_name.CN = cur_config['bindIp']
    #cs_name.CN = platform.node()
    #cert.set_subject(cs_name)
    #cert.set_issuer_name(cs_name)
    #cert.set_not_before(cur_time)
    #cert.set_not_after(expire_time)
    #cert.sign(pkey, md="sha512")
    #cert.save_pem(cur_config['certs']['webserver_cert'])
def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    headers['Content-Security-Policy'] = "default-src='self'"
    headers['Strict-Transport-Security'] = 'max-age=3600'
if __name__ == '__main__':
    server_config = core.MinervaConfigs(conf=os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')).conf['Webserver']['web']
    if not os.path.exists(server_config['certs']['webserver_cert']) or not os.path.exists(server_config['certs']['webserver_cert']):
        genKey(server_config)
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
                          })
    cherrypy.quickstart(Minerva())
