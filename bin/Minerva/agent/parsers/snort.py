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
import re

class ConvertFast():
    def __init__(self, sensor):
        self.sensor = sensor
    def convert(self, entry):
        matches = re.match(r'(?P<timestamp>\d+/\d+/\d+-\d+:\d+:\d+.\d+)'r'(\s+\[\*\*\]\s+)(\[)'r'(?P<gid>\d+)'r'(:)'r'(?P<sid>\d+)'r'(:)'r'(?P<rev>\d+)'r'(])'r'(?P<sig_name>.*)'r'(\[\*\*\])'r'( \[Classification: )'r'(?P<category>.*)'r'(\] \[Priority: )'r'(?P<priority>\d+)'r'(\] \{)'r'(?P<proto>\w+)'r'(\} )'r'(?P<src_ip>\d+.\d+.\d+.\d+)'r'(:)'r'(?P<src_port>\d+)'r'( -> )'r'(?P<dest_ip>\d+.\d+.\d+.\d+)'r'(:)'r'(?P<dest_port>\d+)', entry)
        return_dict = {}
        return_dict['src_port'] = matches.group('src_port')
        return_dict['src_ip'] = matches.group('src_ip')
        return_dict['dest_ip'] = matches.group('dest_ip')
        return_dict['dest_port'] = matches.group('dest_port')
        return_dict['proto'] = matches.group('proto')
        return_dict['timestamp'] = matches.group('timestamp')
        return_dict['alert'] = {}
        return_dict['alert']['category'] = matches.group('category')
        return_dict['alert']['severity'] = matches.group('priority')
        return_dict['alert']['rev'] = matches.group('rev')
        return_dict['alert']['signature_id'] = matches.group('sid')
        return_dict['alert']['gid'] = matches.group('gid')
        return_dict['alert']['signature'] = matches.group('sig_name')
        return_dict['sensor'] = self.sensor
        return_dict['logType'] = 'alert'
        return_dict['MINERVA_STATUS'] = 'OPEN'
        return return_dict
