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

import datetime
import time
import re
import hashlib
import uuid

import pymongo

class Users(object):

    def __init__(self, minerva_core):
        db_conf = minerva_core.conf['Webserver']['db']
        db = minerva_core.get_db()
        #self.salt = db_conf['SECRET_KEY']
        self.users = db.users
        self.sessions = db.sessions
        self.session_salt = db_conf['SESSION_KEY']
        self.web_conf = minerva_core.conf['Webserver']['web']
        self.password_req = self.web_conf['password_requirements']
        self.password_tries = self.password_req['password_tries']
        self.password_min_length = self.password_req['password_min_length']

    def new_pw_checker(self, password):
        pw_length = len(password)
        digit_count = len(re.findall(r"\d", password))
        upper_count = len(re.findall(r"[A-Z]", password))
        lower_count = len(re.findall(r"[a-z]", password))
        special_count = len(re.findall(r"[^A-z0-9]", password))
        pw_check = {}

        if pw_length < int(self.password_min_length):
             pw_check['pw_length'] = pw_length

        if digit_count < int(self.password_req['digit_count']):
             pw_check['digit_count'] = digit_count

        if upper_count < int(self.password_req['upper_count']):
             pw_check['upper_count'] = upper_count

        if lower_count < int(self.password_req['lower_count']):
             pw_check['lower_count'] = lower_count

        if special_count < int(self.password_req['special_count']):
             pw_check['special_count'] = special_count

        return pw_check

    def login(self, username, password, session):
        user_results = list(self.users.find({ "USERNAME": username, "ENABLED": "true" }))

        if len(user_results) == 1:
            hashed = hashlib.sha512(str(password) + str(user_results[0]['SALT'])).hexdigest()
            if 'PASSWORD' in user_results[0]:
                if user_results[0]['PASSWORD'] == hashed:
                    session_hash = hashlib.sha512('%s-%s-%s' % ( str(time.time()), str(username), self.session_salt)).hexdigest()
                    self.sessions.insert({ "session_id": session_hash, "last_accessed": datetime.datetime.utcnow(), "USERNAME": username})
                    session['SESSION_KEY'] = session_hash
                    self.users.update ({ "USERNAME": username }, { "$set": { "pass_failed": 0, "last_login": datetime.datetime.utcnow()}})

                    return True

                else:
                    if 'pass_failed' in user_results[0]:
                        tries = int(user_results[0]['pass_failed'])

                    else:
                        tries = 0

                    tries = int(tries) + 1 
                    if tries >= int(self.password_tries):
                        self.users.update({"USERNAME": username }, { "$set": { "ENABLED": "false", "pass_failed": tries}})

                    else:
                        self.users.update({"USERNAME": username }, { "$set": { "pass_failed": tries }})

        return False


    def get_username(self, session_id):
        user_results = list(self.sessions.find({"session_id": session_id}))
        username = ''

        if len(user_results) > 0:
            username = user_results[0]['USERNAME']

        return username


    def get_permissions(self, session_id):
        user_results = list(self.sessions.find({"session_id": session_id}))

        if len(user_results) > 0:
            perm_results = list(self.users.find({"USERNAME": user_results[0]['USERNAME']}))
            
            if (datetime.datetime.utcnow()-perm_results[0]['PASSWORD_CHANGED']).total_seconds() > (self.web_conf['password_requirements']['password_max_age']*86400):
                return ['PasswordReset']

            if len(perm_results) > 0:
                perms = ['console', 'responder', 'sensor_admin', 'user_admin', 'server_admin']
                results = []

                for p in perms:
                    if perm_results[0][p] == 'true':
                        results.append(p)

                self.sessions.update({"session_id": session_id},{"$set": {"last_accessed": datetime.datetime.utcnow()}})
                return results

            else:
                return ["DoesNotExist"]

        else:
            return ["newLogin"]


    def logout(self, username, session):
        self.sessions.remove({"session_id": session['session_id']})

        try:
            del session['session_id']

        except KeyError:
            pass

        return True


    def create_user(self, username, password, console, responder, sensor_admin, user_admin, server_admin, enabled):
        user_results = list(self.users.find({ "USERNAME": username}))

        if len(user_results) > 0:
            return "Username Already Exists"

        pw_check = self.new_pw_checker(password)

        if len(pw_check) > 0:
            return "Password Check Failed"

        user_salt = uuid.uuid4().hex
        hashed = hashlib.sha512(str(password) + user_salt).hexdigest()

        self.users.insert({
             "date_created": datetime.datetime.utcnow(), 
             "date_modified": datetime.datetime.utcnow(), 
             "USERNAME": username, 
             "SALT": user_salt,
             "PASSWORD": hashed, 
             "console": console, 
             "responder": responder, 
             "sensor_admin": sensor_admin, 
             "user_admin": user_admin, 
             "server_admin": server_admin, 
             "ENABLED": enabled, 
             "pass_failed": 0, 
             "PASSWORD_CHANGED": datetime.datetime.utcnow() 
        })
        return "Success"


    def modify_user(self, username, password, console, responder, sensor_admin, user_admin, server_admin, enabled):
        pw_check = self.new_pw_checker(password)

        if len(pw_check) > 0:
            return "Password Check Failed"

        user_salt = uuid.uuid4().hex
        hashed = hashlib.sha512(str(password) + user_salt).hexdigest()

        self.users.update({
            "USERNAME": username 
            }, { 
            "$set": {
                 "pass_failed": 0, 
                 "date_created": datetime.datetime.utcnow(), 
                 "date_modified": datetime.datetime.utcnow(), 
                 "USERNAME": username, 
                 "SALT": user_salt,
                 "PASSWORD": hashed, 
                 "console": console, 
                 "responder": responder, 
                 "sensor_admin": sensor_admin, 
                 "user_admin": user_admin, 
                 "server_admin": server_admin, 
                 "ENABLED": enabled, 
                 "PASSWORD_CHANGED": datetime.datetime.utcnow() 
            }})

        return "Success"


    def disableUser(self, username, password):
        self.users.update({"USERNAME": username}, { "$set": { "date_modified": datetime.datetime.utcnow(), "ENABLED": False}})

        return


    def changePerms(self, username, console, responder, sensor_admin, user_admin, server_admin, enabled):
        self.users.update({"USERNAME": username}, {"$set": { "console": console, "responder": responder, "sensor_admin": sensor_admin, "user_admin": user_admin, "server_admin": server_admin, "ENABLED": enabled, "date_modified": datetime.datetime.utcnow() }})

        return 'Success'


    def getAllUsers(self):
        active_users = list(self.users.aggregate([{"$match": { "ENABLED": "true"}}, { "$project": { "ID": "$_id", "USERNAME": "$USERNAME", "console": "$console", "responder": "$responder", "sensor_admin": "$sensor_admin", "user_admin": "$user_admin", "server_admin": "$server_admin", "date_created": "$date_created", "date_modified": "$date_modified", "last_login": "$last_login", "ENABLED": "$ENABLED" }}]))

        disabled_users = list(self.users.aggregate([{"$match": { "ENABLED": "false"}}, { "$project": { "ID": "$_id", "USERNAME": "$USERNAME", "responder": "$responder", "sensor_admin": "$sensor_admin", "user_admin": "$user_admin", "server_admin": "$server_admin", "date_created": "$date_created", "date_modified": "$date_modified", "last_login": "$last_login", "ENABLED": "$ENABLED" }}]))

        users = active_users + disabled_users

        return users


    def changePW(self, session_id, current_pw, new_pw):
        pw_check = self.new_pw_checker(new_pw)

        if len(pw_check) > 0:
            return "Password Check Failed"

        user_results = list(self.sessions.find({"session_id": session_id}))

        if len(user_results) > 0:        
            username = user_results[0]['USERNAME']
            results = self.users.find({"USERNAME": username})
            old_salt = results['SALT']
            oldhash = hashlib.sha512(str(current_pw) + old_salt).hexdigest()

            if oldhash == results[0]['PASSWORD']:
                user_salt = uuid.uuid4().hex
                self.users.update({"USERNAME": username}, { "$set": { "PASSWORD": newhash, "pass_failed": 0, "PASSWORD_CHANGED": datetime.datetime.utcnow(), "SALT": user_salt }})

                return "success"

            else:
                return "badOldPass"

        else:
            return "newLogin"

