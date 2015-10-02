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

class MinervaConfigs():
    def __init__(self, **kwargs):
        if not 'conf' in kwargs:
            conf = '/opt/minerva/etc/minerva.yaml'
        if not os.path.exists(conf):
            raise "Config File not found"
        with open(conf,'r') as f:
            config = yaml.load(f)
        if not 'client_cert' in config or not 'client_private' in config:
            raise "Invalide Config"
        self.conf = config
class TailLog():
    def __init__(self, logFile, posFile, logType):
        self.logFile = logFile
        self.logType = logType
        self.posFile = posFile
        self.pos = 0
        self.pos_inode = 0
        self.pos_size = 0
    def write_pos(self):
        write_line = str(self.pos_inode) + ',' + str(self.pos_size) + ',' + str(self.pos)
        with open(self.posFile, 'w') as pfile:
            pfile.write(write_line)
    def tail(self):
        try:
            #def write_pos():
                #pfile = open(self.posFile,'w')
                #pfile.write(str(inode) + ',' + str(size) + ',' + str(pos))
                #pfile.flush()
                #pfile.close()
                #write_line = str(inode) + ',' + str(size) + ',' + str(pos)
                #write_line = str(self.pos_inode) + ',' + str(self.pos_size) + ',' + str(self.pos)
                #with open(self.posFile, 'w') as pfile:
                    #pfile.write(write_line)
            def reset_file():
                print('omg reset file')
                lfile.close()
                lfile = open(self.logFile,'r')
                stat = os.fstat(lfile.fileno())
                cur_inode = stat.st_ino
                cur_size = stat.st_size
                pos_inode = cur_inode
                pos_size = cur_size
                pos = 0
                self.pos_inode = cur_inode
                self.pos_size = cur_size
                self.pos = pos
                self.write_pos()
                return pos_inode, pos_size, pos
            if os.path.exists(self.posFile):
                try:
                    pos_inode, pos_size, pos = open(self.posFile,'r').readlines()[0].split(',')
                    pos = int(pos)
                    pos_inode = int(pos_inode)
                    pos_size = int(pos_size)
                    self.pos = pos
                    self.pos_inode = pos_inode
                    self.pos_size = pos_size
                except:
                    print('error reading inode')
                    pos = 0
                    pos_inode = 0
                    pos_size = 0
            else:
                print('pos file doesnt exist')
                pos = 0
                pos_inode = 0
                pos_size = 0
            if os.path.exists(self.logFile):
                print('opening file')
                lfile = open(self.logFile,'r')
                stat = os.fstat(lfile.fileno())
                cur_inode = stat.st_ino
                cur_size = stat.st_size
                print('done getting inode')
                if cur_inode != pos_inode or cur_size < pos_size:
                    print('diff inode')
                    print(pos_size)
                    print(cur_size)
                    pos = 0
                    pos_inode = cur_inode
                    pos_size = cur_size
                    self.pos_inode = cur_inode
                    self.pos_size = cur_size
                    self.write_pos()
                sleep = 0.00001
                count = 0
                while True:
                    line = lfile.readline()
                    if count < pos:
                        if not line:
                            print('not enough lines')
                            stat = os.stat(self.logFile)
                            act_inode = stat.st_ino
                            act_size = stat.st_size
                            if pos_inode != act_inode or act_size < pos_size:
                                print('done getting inode2')
                                pos_inode, pos_size, pos = reset_file()
                                cur_inode = pos_inode
                                cur_size = pos_size
                                count = 0
                        else:
                            count += 1
                        continue
                    if not line:
                        stat = os.stat(self.logFile)
                        act_inode = stat.st_ino
                        act_size = stat.st_size
                        if pos_inode != act_inode or act_size < pos_size:
                            pos_inode, pos_size, pos = reset_file()
                            cur_inode = pos_inode
                            cur_size = pos_size
                            count = 0
                            continue
		        print('sleeping')
                        time.sleep(sleep)
                        if sleep < 10:
                            sleep += .5
                        continue
                    count += 1
                    pos += 1
                    self.pos = pos
                    self.write_pos()
                    sleep = 0.00001
                    yield line
            else:
                raise "File not found"
        except:
            self.write_pos()
            sys.exit()
class ConvertJSON():
    def __init__(self, sensor, logType):
        self.sensor = sensor
        self.logType = logType
    def convert(self, entry):
        try:
            new_entry = json.loads(entry)
        except:
            print(entry)
            raise "Invalid JSON"
        new_entry['sensor'] = self.sensor
        new_entry['logType'] = self.logType
        new_entry['MINERVA_STATUS'] = 'OPEN'
        return new_entry
