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

def _convertJSON(entry, sensor):
    try:
        new_entry = json.loads(entry)

    except ValueError:
        return False

    new_entry['sensor'] = sensor
    new_entry['MINERVA_STATUS'] = 'OPEN'
    return new_entry

class ConvertDNS():
    def __init__(self, sensor):
        self.sensor = sensor

    def convert(self, entry):
        new_entry =  _convertJSON(entry, self.sensor)

        try:
            if new_entry['event_type'] == 'flow':
                flow = new_entry.pop('flow')
                new_entry['netflow'] = flow
                new_entry['logType'] = 'flow'
    
            elif new_entry['event_type'] == 'alert':
                new_entry['logType'] = 'alert'
    
            elif new_entry['event_type'] == 'netflow':
                new_entry['logType'] = 'flow'
    
            elif new_entry['event_type'] == 'dns':
                new_entry['logType'] = 'dns'
    
            else:
                return False
        except TypeError:
            return False

        return new_entry

class ConvertConn():
    def __init__(self, sensor):
        self.sensor = sensor

    def convert(self, entry):
        new_entry =  _convertJSON(entry, self.sensor)

        try:
            if new_entry['event_type'] == 'flow':
                flow = new_entry.pop('flow')
                new_entry['netflow'] = flow
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'alert':
                new_entry['logType'] = 'alert'

            elif new_entry['event_type'] == 'netflow':
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'dns':
                new_entry['logType'] = 'dns'

            else:
                return False
        except TypeError:
            return False

        return new_entry

class ConvertNotice():
    def __init__(self, sensor):
        self.sensor = sensor

    def convert(self, entry):
        new_entry =  _convertJSON(entry, self.sensor)

        try:
            if new_entry['event_type'] == 'flow':
                flow = new_entry.pop('flow')
                new_entry['netflow'] = flow
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'alert':
                new_entry['logType'] = 'alert'

            elif new_entry['event_type'] == 'netflow':
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'dns':
                new_entry['logType'] = 'dns'

            else:
                return False
        except TypeError:
            return False

        return new_entry

class ConvertJSONDNS():
    def __init__(self, sensor):
        self.sensor = sensor

    def convert(self, entry):
        new_entry =  _convertJSON(entry, self.sensor)

        try:
            if new_entry['event_type'] == 'flow':
                flow = new_entry.pop('flow')
                new_entry['netflow'] = flow
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'alert':
                new_entry['logType'] = 'alert'

            elif new_entry['event_type'] == 'netflow':
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'dns':
                new_entry['logType'] = 'dns'

            else:
                return False
        except TypeError:
            return False

        return new_entry

class ConvertJSONConn():
    def __init__(self, sensor):
        self.sensor = sensor

    def convert(self, entry):
        new_entry =  _convertJSON(entry, self.sensor)

        try:
            if new_entry['event_type'] == 'flow':
                flow = new_entry.pop('flow')
                new_entry['netflow'] = flow
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'alert':
                new_entry['logType'] = 'alert'

            elif new_entry['event_type'] == 'netflow':
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'dns':
                new_entry['logType'] = 'dns'

            else:
                return False
        except TypeError:
            return False

        return new_entry

class ConvertJSONNotice():
    def __init__(self, sensor):
        self.sensor = sensor

    def convert(self, entry):
        new_entry =  _convertJSON(entry, self.sensor)

        try:
            if new_entry['event_type'] == 'flow':
                flow = new_entry.pop('flow')
                new_entry['netflow'] = flow
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'alert':
                new_entry['logType'] = 'alert'

            elif new_entry['event_type'] == 'netflow':
                new_entry['logType'] = 'flow'

            elif new_entry['event_type'] == 'dns':
                new_entry['logType'] = 'dns'

            else:
                return False
        except TypeError:
            return False

        return new_entry
