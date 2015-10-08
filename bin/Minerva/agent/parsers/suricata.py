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

import json
import time
import sys

def _convertJSON(entry, logType, sensor):
    try:
        new_entry = json.loads(entry)
    except:
        #print(entry)
        raise "Invalid JSON"
    new_entry['sensor'] = sensor
    new_entry['logType'] = logType
    new_entry['MINERVA_STATUS'] = 'OPEN'
    return new_entry
class ConvertAlert():
    def __init__(self, sensor):
        self.sensor = sensor
    def convert(self, entry):
        return _convertJSON(entry, 'alert', self.sensor)
class ConvertFlow():
    def __init__(self, sensor):
        self.sensor = sensor
    def convert(self, entry):
        new_entry =  _convertJSON(entry, 'flow', self.sensor)
        if new_entry['event_type'] == 'flow':
            flow = new_entry.pop('flow')
            new_entry['netflow'] = flow
        return new_entry
