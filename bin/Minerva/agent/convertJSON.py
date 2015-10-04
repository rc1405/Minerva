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
import json
import time
import sys

class ConvertJSON():
    def __init__(self, sensor, logType):
        self.sensor = sensor
        self.logType = logType
    def convert(self, entry):
        try:
            new_entry = json.loads(entry)
        except:
            raise "Invalid JSON"
        new_entry['sensor'] = self.sensor
        new_entry['logType'] = self.logType
        new_entry['MINERVA_STATUS'] = 'OPEN'
        return new_entry
