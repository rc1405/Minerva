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
from cStringIO import StringIO

import pymongo

class MinervaSignatures(object):
    '''Setup Initial Parameters'''
    def __init__(self, minerva_core):
        self.sizeLimit = minerva_core.conf['Webserver']['events']['maxResults']
        db = minerva_core.get_db()
        self.signatures = db.signatures
        self.alerts = db.alerts
        self.ruleSizeLimit = 10
        self.ruleFileLimit = 100

    def parse_signatures(self, rule_file):
        sid_regex = re.compile(r'sid: *(?P<sid>\d+) *;')
        rev_regex = re.compile(r'rev: *(?P<rev>\d+) *;')
        gid_regex = re.compile(r'gid: *(?P<gid>\d+) *;')
        classtype_regex = re.compile(r'classtype: *(?P<classtype>\S+) *;')
        #classtypes = []
        bad_sigs = 0
        good_sigs = 0
      
        for row in rule_file:
            if row[:1] == '#' or row == '\n':
                continue
            sid = sid_regex.findall(row)
            if len(sid) == 0:
                bad_sigs += 1
                continue
            else:
                sid = int(sid[0])
                good_sigs += 1
            rev = rev_regex.findall(row)
            if len(rev) == 0:
                rev = 1
            else:
                rev = int(rev[0])
            gid = gid_regex.findall(row)
            if len(gid) == 0:
                gid = 1
            else:
                gid = int(gid[0])
            classtype = classtype_regex.findall(row)
            if len(classtype) == 0:
                classtype = ''
            else:
                classtype = classtype[0]
            self.signatures.update({"sig_id": sid, "gen_id": gid, "rev": rev}, { "$set": {"sig_id": sid, "gen_id": gid, "rev": rev, "classtype": classtype, "signature": row.strip(), "type": "signature" }}, upsert=True )
        return good_sigs, bad_sigs

    def unzip_signatures(self, rule_file):
        file_count = 0
        good_sigs = 0
        bad_sigs = 0
        try:
            zip_file = zipfile.ZipFile(StringIO(rule_file.read()))
        except:
            return 'Unable to open zip file'
        contents = zip_file.namelist()
        for filename in contents:
            if filename.endswith('.rules'):
                file_count += 1
                good, bad = self.parse_signatures(zip_file.read(filename).split('\n'))
                good_sigs = good_sigs + good
                bad_sigs = bad_sigs + bad
        return file_count, good_sigs, bad_sigs

    def untar_signatures(self, tar_file):
        file_count = 0
        good_sigs = 0
        bad_sigs = 0
        try:
            tar = tarfile.open(fileobj=StringIO(tar_file.read()))
        except:
            return 'Unable to open tar file'
        for member in tar.getmembers():
            if member.name.endswith('.rules'):
                file_count += 1
                good, bad = self.parse_signatures(tar.extractfile(member).readlines())
                good_sigs = good_sigs + good
                bad_sigs = bad_sigs + bad
        return file_count, good_sigs, bad_sigs

    def process_files(self, initial_file):
        file_name = initial_file.filename
        file_count = 0
        good_sigs = 0
        bad_sigs = 0
        if '.' in file_name:
            file_name_tmp = file_name.split('.')
            if file_name_tmp[-2] == 'tar' or file_name_tmp[-1] == 'tar':
                file_count, good_sigs, bad_sigs = self.untar_signatures(initial_file.file)
            elif file_name_tmp[-1] in ['gz', 'gzip', 'zip']:
                file_count, good_sigs, bad_sigs = self.unzip_signatures(initial_file.file)
            elif file_name_tmp[-1] == 'rules':
                file_count = 1
                good_sigs, bad_sigs = self.parse_signatures(initial_file.file.readlines())
        return file_count, good_sigs, bad_sigs

    def get_classtypes(self):
        return self.signatures.distinct("classtype")

    def get_signature(self, events):
        all_signatures = {}
        for event in events:
            results = list(self.alerts.aggregate([{"$match": { "_id": bson.objectid.ObjectId(event)}},{"$project": { "sig_id": "$alert.signature_id", "rev": "$alert.rev", "gid": "$alert.gid"}}]))
            if len(results) == 0:
                all_signatures[event] = ''
            else:
                signature = list(self.signatures.aggregate([{"$match": { "type": "signature", "sig_id": results[0]['sig_id'], "rev": results[0]['rev'], "gen_id": results[0]['gid']}},{"$project": {"signature": "$signature"}}]))
                if len(signature) > 0:
                    all_signatures[event] = signature[0]['signature']
                else:
                    all_signatures[event] = ''

        return all_signatures

