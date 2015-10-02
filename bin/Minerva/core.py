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

class MinervaConfigs():
    def __init__(self, **kwargs):
        if not 'conf' in kwargs:
            conf = os.path.join(os.path.abspath(os.pardir), 'etc/minerva.yaml')
        else:
            conf = kwargs['conf']
        if not os.path.exists(conf):
            raise "Config File not found"
        with open(conf,'r') as f:
            config = yaml.load(f)
        self.conf = config
    def parse_web_configs(self, new_config):
        config = self.conf
        config['Webserver']['db']['url'] = new_config['db_ip']
        config['Webserver']['db']['port'] = int(new_config['db_port'])
        if not str(config['Webserver']['db']['useAuth']) == 'false':
            config['Webserver']['db']['useAuth'] = 'False'
            config['Webserver']['db']['username'] = new_config['db_user']
            if len(str(new_config['db_pass'])) > 0:
                config['Webserver']['db']['password'] = new_config['db_pass']  
        else:
            config['Webserver']['db']['useAuth'] = 'True'
        config['Webserver']['web']['port'] = int(new_config['web_port'])
        config['Webserver']['web']['hostname'] = str(new_config['web_host'])
        config['Webserver']['web']['bindIp'] = new_config['web_ip']
        config['Webserver']['web']['web_threads'] = int(new_config['web_threads'])
        config['Webserver']['web']['password_tries'] = int(new_config['pass_tries'])
        config['Webserver']['web']['password_max_age'] = int(new_config['pass_age'])
        config['Webserver']['web']['password_min_length'] = int(new_config['pass_min'])
        config['Webserver']['web']['certs']['server_cert'] = str(new_config['cert_path'])
        config['Webserver']['web']['certs']['server_key'] = str(new_config['key_path'])
        config['Webserver']['web']['session_timeout'] = int(new_config['session_timeout'])
        if int(new_config['max_events']) > 15000:
            config['Webserver']['events']['max_events'] = 15000
        else:
            config['Webserver']['events']['max_events'] = int(new_config['max_events'])
        config['Webserver']['events']['max_age'] = int(new_config['max_age'])
        config['Webserver']['events']['flow_max_index_age'] = int(new_config['flow_age'])

        return config
