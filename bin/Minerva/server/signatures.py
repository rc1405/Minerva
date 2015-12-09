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
import datetime
import bson
import re
import zipfile
import tarfile

import pymongo

class signatures(object):
    '''Setup Initial Parameters'''
    def __init__(self, minerva_core):
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']
        db = minerva_core.get_db()
        self.signatures = db.signatures
        self.ruleSizeLimit = 10
        self.ruleFileLimit = 100

    def parse_signatures(self, rule_files):
        sid_regex = re.compile(r'sid:(?P<sid>\d+)\w+;')
        rev_regex = re.compile(r'rev:(?P<rev>\d+)\w+;')
        gid_regex = re.compile(r'gid:(?P<gid>\d+)\w+;')
        classtype_regex = re.compile(r'classtype:(?P<classtype>\S+);')
        output = []
        classtypes = []
      
        for row in rule_file:
            sid = sid_regex.findall(row)
            if len(sid) == 0:
                continue
            else:
                sid = sid[0]
            rev = rev_regex.findall(row)
            if len(rev) == 0:
                rev = 1
            else:
                rev = rev[0]
            gid = gid_regex.findall(row)
            if len(gid) == 0:
                gid = 1
            else:
                gid = gid[0]
            classtype = classtype_regex.findall(row)
            if len(classtype) == 0:
                classtype = ''
            else:
                classtype = classtype[0]
            if not classtype in classtypes:
                classtypes.append(classtype)
            output.append({ "SID": str(sid), "REV": str(rev), "GID": str(gid), "Classtype": classtype, "Signature": row.strip()})
        return output, classtypes

    def insert_signatures(self, signatures);
        for sig in signatures:
            deleted = self.signatures.delete_many(sig)
            self.signatures.insert(sig)
        return

    def unzip_signatures(self, rule_file):
        bad_files = []
        file_count = 0
        zip_file = zipfile.ZipFilel(rule_file)
        contents = zip_file.namelist()
        for filename in contents:
            fileinfo = zip_file.getinfo(name)
            if fileinfo.file_size > self.ruleSizeLimit:
                bad_files.append(filename)
                continue
            file_buffer = zip_file.read(filename)
            if len(file_buffer) > self.ruleSizeLimit:
                continue
            write_temp_file with buffer
            file_count += 1 
            if file_count >= self.ruleFileLimit:
                break
        return tmp files

    def untar_signatures(self, signatures):
        do stuff to untar here

    def process_files(self, initial_file):
        determine what type and send to other processes
        return 'good or bad things'
