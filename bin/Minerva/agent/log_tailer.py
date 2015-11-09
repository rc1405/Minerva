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
import json
import time
import sys

class TailLog():
    def __init__(self, logFile, posFile):
        self.logFile = logFile
        self.posFile = posFile
        self.pos = 0
        self.pos_inode = 0
        self.pos_size = 0
    def write_pos(self):
        write_line = "%s,%s,%s" % (str(self.pos_inode),str(self.pos_size),str(self.pos))
        with open(self.posFile, 'w') as pfile:
            pfile.write(write_line)
    def tail(self):
        try:
            def reset_file():
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
                    pos = 0
                    pos_inode = 0
                    pos_size = 0
            else:
                pos = 0
                pos_inode = 0
                pos_size = 0
            if os.path.exists(self.logFile):
                lfile = open(self.logFile,'r')
                stat = os.fstat(lfile.fileno())
                cur_inode = stat.st_ino
                cur_size = stat.st_size
                if cur_inode != pos_inode or cur_size < pos_size:
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
                            stat = os.stat(self.logFile)
                            act_inode = stat.st_ino
                            act_size = stat.st_size
                            if pos_inode != act_inode or act_size < pos_size:
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
