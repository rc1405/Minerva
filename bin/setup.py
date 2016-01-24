import logging
import os
import sys
import ssl
import copy
import datetime
import time
import shutil
import getpass
import uuid
import hashlib
import platform
import re

def check_server():
    try:
        import pymongo
        logger.info('%s is installed' % 'pymongo')
    except:
        print('Pymongo not installed')
        logger.info('Pymongo not installed')
        sys.exit()
    try:
        import M2Crypto
        logger.error('%s is installed' % 'M2Crypto')
    except:
        print('M2Crypto not installed')
        logger.error('M2Crypto not installed')
        sys.exit()
    try:
        import cherrypy
        logger.info('%s is installed' % 'cherrypy')
    except:
        print('Cherrypy not installed')
        logger.error('Cherrypy not installed')
        sys.exit()
    try:
        import jinja2
        logger.info('%s is installed' % 'jinja2')
    except:
        print('Jinja2 not installed')
        logger.error('Jinja2 not installed')
        sys.exit()
    try:
        import yaml
        logger.info('%s is installed' % 'pyyaml')
    except:
        print('PyYAmL not installed')
        logger.error('PyYAmL not installed')
        sys.exit()
    try:
        import dateutil
        logger.info('%s is installed' % 'dateutil')
    except:
        print('python-dateutil not installed')
        logger.error('python-dateutil not installed')
        sys.exit()
    try:
        import pytz
        logger.info('%s is installed' % 'pytz')
    except:
        print('pytz not installed')
        logger.error('pytz not installed')
        sys.exit()

def check_agent():
    try:
        import M2Crypto
        logger.info('%s is installed' % 'M2Crypto')
    except:
        print('M2Crypto not installed')
        logger.error('M2Crypto not installed')
        sys.exit()
    try:
        import yaml
        logger.info('%s is installed' % 'pyyaml')
    except:
        print('PyYAmL not installed')
        sys.exit()
    try:
        import pytz
        logger.info('%s is installed' % 'pytz')
    except:
        print('pytz not installed')
        logger.error('pytz not installed')

def check_receiver():
    try:
        import yaml
        logger.info('%s is installed' % 'pyyaml')
    except:
        print('PyYAmL not installed')
        logger.error('PyYAmL not installed')
        sys.exit()
    try:
        import M2Crypto
        logger.info('%s is installed' % 'M2Crypto')
    except:
        print('M2Crypto not installed')
        logger.error('M2Crypto not installed')
        sys.exit()
    try:
        import pymongo
        logger.info('%s is installed' % 'pymongo')
    except:
        print('Pymongo not installed')
        logger.error('Pymongo not installed')
        sys.exit()
    try:
        import pytz
        logger.info('%s is installed' % 'pytz')
    except:
        print('pytz not installed')
        logger.error('pytz not installed')
    try:
        import numpy
        logger.info('%s is installed' % 'numpy')
    except:
        print('numpy not installed')
        logger.error('numpy not installed')
        sys.exit()
    try:
        import netaddr
        logger.info('%s is installed' % 'netaddr')
    except:
        print('netaddr not installed')
        logger.error('netaddr not installed')
        sys.exit()

def validate_ip(ipaddress):
    if len(re.findall(r'\d+.\d+.\d+.\d+', ipaddress)) == 1:
        retval = True
        for i in ipaddress.split('.'):
            if int(i) > 255:
                retval = False
        return retval
    else:
        return False

def setup_db_lite():
    import pymongo
    print("Setting Up Receiver DB connection")
    logger.info("Setting Up Receiver DB connection")
    
    while True:
        ip = raw_input('Please enter database ip: [127.0.0.1] ')
        if len(ip) == 0:
            ip = '127.0.0.1'
            break
        elif validate_ip(ip):
            break
        else:
            print('Invalid IP Adress')
    logger.info("DB Ip is set to %s" % ip)

    while True:
        port = raw_input('Please enter database port: [27017] ')
        if len(port) == 0:
            port = 27017
            break
        else:
            try:
                port = int(port)
                break
            except:
                print('Invalid port')
                pass
    logger.info("DB Port is set to %i" % int(port))

    while True:
        useAuth = raw_input('Use db authentication? Y/N [N] ')
        if useAuth == 'y' or use_auth == 'Y' or use_auth == 'n' or use_auth == 'N' or len(use_auth) == 0:
            break
        else:
            print('Invalid db auth option')
    logger.info('Use DB Auth is set to %s' % useAuth)
    if useAuth == 'y' or useAuth == 'Y':
        while True:
            print("Pick an Authentication Type\n\t1) Username/Password\n\t2) X509\n")
            choice = raw_input()
            try:
                if int(choice) == 1:
                    authType = 'Password'
                    break
                elif int(choice) == 2:
                    authType = 'X509'
                    break
            except:
                print('Invalid Option')
                pass
        logger.info('DB Auth Type is %s' % authType)
        while True:
            username = raw_input("Enter a username: ")
            if len(username) > 0:
                break
            else:
                print('No username selected')
        logger.info('DB Username chosen is %s' % username)
        if authType == 'X509':
            while True:
                auth_cert = raw_input("Enter full path to cert used for authentication: ")
                if len(auth_cert) == 0:
                    print('No path specified')
                    continue
                if not os.path.exists(auth_cert):
                    print('Cert does not exist')
                    continue
                break
            logger.info('Auth Cert path is %s' % auth_cert)
            while True:
                auth_ca = raw_input("Enter full path to ca_certs to be used: ")
                if len(auth_ca) == 0:
                    print('No path specified')
                    continue
                if not os.path.exists(auth_ca):
                    print('Cert does not exist')
                    continue
                break
            logger.info('Auth CA path is %s' % auth_ca)
            try:
                client = pymongo.MongoClient(ip, int(port),
                                             ssl=True,
                                             ssl_certfile=auth_cert,
                                             ssl_cert_reqs=ssl.CERT_REQUIRED,
                                             ssl_ca_certs=auth_ca)
                client.minerva.authenticate(db_conf['username'], mechanism='MONGODB-X509')
            except:
                print("Unable to connect to DB")
                logger.error("Unable to connect to DB")
                sys.exit()
        elif authType == 'Password':
            while True:
                print('Enter a password: ')
                password = getpass.getpass()
                print('Re-Enter the password: ')
                password1 = getpass.getpass()
                if password == password1:
                    break
                else:
                    print("Passwords do not match")
            logger.info('DB Password Entered')
            while True:
                choice = raw_input("Enter Password Mechanism:\n\t1) SCRAM-SHA-1 [Default MONGODB Option]\n\t2) MONGODB-CR\n")
                try:
                    if int(choice) == 1:
                        PW_Mechanism = "SCRAM-SHA-1"
                        break
                    elif int(choice) == 2:
                        PW_Mechanism = "MONGODB-CR"
                        break
                except:
                    print("Invalid Option")
                    pass
            logger.info("DB Password Mechanism chosen is %s" % PW_Mechanism)
            client = pymongo.MongoClient(ip,int(port))
            try:
                client.minerva.authenticate(username, password, mechanism=PW_Mechanism)
            except:
                print("Unable to connect to DB")
                logger.error("Unable to connect to DB")
                sys.exit()
        useAuth = True
    else:
        logger.info('No DB Auth Chosen')
        useAuth = False
        client = pymongo.MongoClient(ip,int(port))

    user = client.minerva.users.findOne()
    if len(user) > 0:
        if not 'SALT' in user:
            print('User Hashing has changed and will require passwords to be reset')
            logger.info('User Hashing has changed and will require passwords to be reset')
            while True:
                user_name = raw_input("Enter username of admin user to create or modify: ")
                if len(user_name) == 0:
                    print('User name not entered')
                    continue
                elif len(user_name) < 5:
                    print('User name too short')
                    continue
                break
            while True:
                print('Enter password: ')
                admin_pw = getpass.getpass()
                print('Re-enter password: ')
                admin_pw2 = getpass.getpass()
                if admin_pw == admin_pw2:
                    break
                else:
                    print("Passwords do not match")
            logger.info("Creating admin user %s" % user_name)
            password_salt = uuid.uuid4().hex
            admin_hashedPW = hashlib.sha512(str(admin_pw) + str(password_salt)).hexdigest()
            client.minerva.users.update({}, { "$set": { "SALT": uuid.uuid4().hex }}, upsert=True, multi=True )
            if len(list(db.users.find({"USERNAME": user_name }))) > 0:
                db.users.remove({"USERNAME": user_name})
            db.users.insert(
            {
                    "USERNAME" : user_name,
                    "user_admin" : "true",
                    "ENABLED" : "true",
                    "SALT": password_salt,
                    "PASSWORD" : admin_hashedPW,
                    "console" : "true",
                    "date_modified" : datetime.datetime.utcnow(),
                    "sensor_admin" : "true",
                    "responder" : "true",
                    "event_filters": "true",
                    "server_admin" : "true",
                    "date_created" : datetime.datetime.utcnow(),
                    "PASSWORD_CHANGED": datetime.datetime.utcnow(),
            })

    while True:
        sessionMinutes = raw_input("Enter number of minutes until each console session times out: ")
        try:
            sessionMinutes = int(sessionMinutes)
            break
        except:
            print('Invalid Option')
            pass

    logger.info("Session timeout %s minutes" % sessionMinutes)

    config['Webserver'] = {}
    config['Webserver']['db'] = {}
    config['Webserver']['db']['url'] = ip
    config['Webserver']['db']['port'] = port
    config['Webserver']['db']['useAuth'] = useAuth
    if useAuth:
        config['Webserver']['db']['username'] = username
        if authType == 'X509':
            config['Webserver']['db']['auth_cert'] = auth_cert
            config['Webserver']['db']['auth_ca'] = auth_ca
        elif authType == 'Password':
            config['Webserver']['db']['password'] = password
            config['Webserver']['db']['PW_Mechanism'] = PW_Mechanism
        config['Webserver']['db']['AuthType'] = authType
    config['Webserver']['web'] = {}
    config['Webserver']['web']['session_timeout'] = sessionMinutes
    config['Webserver']['events'] = {}

def setup_db():
    import pymongo
    print("**********************************************************")
    print("*               Setting up the Database                  *")
    print("**********************************************************")
    logger.info("Setting up the Database")
    while True:
        ip = raw_input('Please enter database ip: [127.0.0.1] ')
        if len(ip) == 0:
            ip = '127.0.0.1'
            break
        elif validate_ip(ip):
            break
        else:
            print('Invalid IP')
    logger.info('Database IP is %s' % ip)
    while True:
        port = raw_input('Please enter database port: [27017] ')
        if len(port) == 0:
            port = 27017
            break
        else:
            try:
                port = int(port)
                break
            except:
                print('Invalid port')
                pass
    logger.info('Database Port is %i' % int(port))
    print("****IF AUTHENTICATION METHOD IS CHOSEN, IT MUST BE SETUP PRIOR TO RUNNING SETUP*****")
    while True:
        useAuth = raw_input('Use db authentication? Y/N [N] ')
        if useAuth == 'y' or useAuth == 'Y' or useAuth == 'n' or useAuth == 'N' or len(useAuth) == 0:
            break
        else:
            print('Invalid db auth option')
    logger.info('Use DB Auth is set to %s' % useAuth)
    if useAuth == 'y' or useAuth == 'Y':
        while True:
            print("Pick an Authentication Type\n\t1) Username/Password\n\t2) X509\n")
            choice = raw_input()
            try:
                if int(choice) == 1:
                    authType = 'Password'
                    break
                elif int(choice) == 2:
                    authType = 'X509'
                    break
            except:
                print('Invalid Option')
                pass
        logger.info('DB Auth Type is %s' % authType)
        while True:
            username = raw_input("Enter a username: ")
            if len(username) > 0:
                break
            else: 
                print('No username entered')
        logger.info('DB Username chosen is %s' % username)
        if authType == 'X509':
            while True:
                auth_cert = raw_input("Enter full path to cert used for authentication: ")
                if len(auth_cert) == 0:
                    print('No Auth cert entered')
                    continue
                if not os.path.exists(auth_cert):
                    print('Auth cert does not exist')
                    continue
                break
            logger.info('Auth Cert path is %s' % auth_cert)
            while True:
                auth_ca = raw_input("Enter full path to ca_certs to be used: ")
                if len(auth_ca) == 0:
                    print('No CA file entered')
                    continue
                if not os.path.exists(auth_ca):
                    print('CA file doens\'t exist')
                    continue
                break
            logger.info('Auth CA path is %s' % auth_ca)
            try:
                client = pymongo.MongoClient(ip, int(port),
                                             ssl=True,
                                             ssl_certfile=auth_cert,
                                             ssl_cert_reqs=ssl.CERT_REQUIRED,
                                             ssl_ca_certs=auth_ca)
                client.minerva.authenticate(db_conf['username'], mechanism='MONGODB-X509')
            except:
                print("Unable to connect to DB")
                logger.error("Unable to connect to DB")
                sys.exit()
        elif authType == 'Password':
            while True:
                print('Enter a password: ')
                password = getpass.getpass()
                print('Re-Enter the password: ')
                password1 = getpass.getpass()
                if password == password1:
                    break
                else:
                    print("Passwords do not match")
            logger.info('DB Password Entered')
            while True:
                choice = raw_input("Enter Password Mechanism:\n\t1) SCRAM-SHA-1 [Default MONGODB Option]\n\t2) MONGODB-CR\n")
                try:
                    if int(choice) == 1:
                        PW_Mechanism = "SCRAM-SHA-1"
                        break
                    elif int(choice) == 2:
                        PW_Mechanism = "MONGODB-CR"
                        break
                except:
                    print("Invalid Option")
                    pass
            logger.info("DB Password Mechanism chosen is %s" % PW_Mechanism)
            client = pymongo.MongoClient(ip,int(port))
            try:
                client.minerva.authenticate(username, password, mechanism=PW_Mechanism)
            except:
                print("Unable to connect to DB")
                logger.error("Unable to connect to DB")
                sys.exit()
        useAuth = True
    else:
        logger.info('No DB Auth Chosen')
        useAuth = False
        client = pymongo.MongoClient(ip,int(port))

    if 'minerva' in client.database_names():
        logger.info('DB exists')
        while True:
            resp = raw_input('Database already exists, do you want to keep it? [N]')
            if resp == 'y' or resp == 'Y' or resp == 'n' or resp == 'N' or len(resp) == 0:
                break
        if resp == 'Y' or resp == 'y':
            logger.info('Keeping Current DB')
            keep_db = True
        else:
            logger.info('Dropping Current DB')
            keep_db = False
            client.drop_database('minerva')
    else:
        keep_db = False

    db = client.minerva
    collections = db.collection_names()
    if keep_db:
        print("Recreating Indexes, this can take some time")
        logger.info("Recreating Indexes, this can take some time")
    logger.info("Creating collections if they do not exist")
    if not 'alerts' in collections:
        db.create_collection('alerts')
    else:
        db.alerts.drop_indexes()
    if not 'filters' in collections:
        db.create_collection('filters')
    else:
        db.filters.drop_indexes()
    if not 'flow' in collections:
        db.create_collection('flow')
    else:
        db.flow.drop_indexes()
    if not 'dns' in collections:
        db.create_collection('dns')
    else:
        db.dns.drop_indexes()
    if not 'certs' in collections:
        db.create_collection('certs')
    if not 'watchlist' in collections:
        db.create_collection('watchlist')
    if not 'signatures' in collections:
        db.create_collection('signatures')
    if not 'sessions' in collections:
        db.create_collection('sessions')
    else:
        db.sessions.drop_indexes()
    if not 'sensors' in collections:
        db.create_collection('sensors')
    if not 'users' in collections:
        db.create_collection('users')
   

    logger.info("Alert search index created is: %s" % '([("MINERVA_STATUS", pymongo.ASCENDING),("epoch", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("alert.signature", pymongo.ASCENDING),("alert.category", pymongo.ASCENDING),("alert.signature_id", pymongo.ASCENDING),("alert.rev", pymongo.ASCENDING),("alert.gid", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="alert-search-index")')

    db.alerts.create_index([("MINERVA_STATUS", pymongo.ASCENDING),("epoch", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("alert.signature", pymongo.ASCENDING),("alert.category", pymongo.ASCENDING),("alert.signature_id", pymongo.ASCENDING),("alert.rev", pymongo.ASCENDING),("alert.gid", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="alert-search-index")


    while True:
        expiredDays = raw_input("Enter number of days to keep alerts: ")
        try:
            expiredDays = int(expiredDays)
            break
        except:
            print('Invalid day option')
            pass
    logger.info("Days to keep alerts %i" % expiredDays)
    expiredSeconds = int(expiredDays) * 86400
    db.alerts.ensure_index("timestamp",expireAfterSeconds=expiredSeconds)

    logger.info("Flow search index created is: %s " % '([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("netflow.start_epoch", pymongo.ASCENDING),("netflow.stop_epoch", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)])')

    db.flow.create_index([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("netflow.start_epoch", pymongo.ASCENDING),("netflow.stop_epoch", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)])

    while True:
        expiredflowDays = raw_input("Enter number of days to keep flow data: ")
        try:
            expiredflowDays = int(expiredflowDays)
            break
        except:
            print('Invalid day option')
            pass

    logger.info("Days to keep flow data %i" % expiredflowDays)
    flowexpiredSeconds = int(expiredflowDays) * 86400
    db.flow.ensure_index("timestamp",expireAfterSeconds=flowexpiredSeconds)

    logger.info("DNS search index created is: %s " % '([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("epoch", pymongo.ASCENDING),("sensor", pymongo.ASCENDING),("dns.type", pymongo.ASCENDING),("dns.rrtype", pymongo.ASCENDING),("dns.rcode", pymongo.ASCENDING),("dns.rrname", pymongo.ASCENDING),("dns.rdata", pymongo.ASCENDING)],name="dns-search-index")')

    db.dns.create_index([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("epoch", pymongo.ASCENDING),("sensor", pymongo.ASCENDING),("dns.type", pymongo.ASCENDING),("dns.rrtype", pymongo.ASCENDING),("dns.rcode", pymongo.ASCENDING),("dns.rrname", pymongo.ASCENDING),("dns.rdata", pymongo.ASCENDING)],name="dns-search-index")

    while True:
        expireddnsDays = raw_input("Enter number of days to keep dns logs: ")
        try:
            expireddnsDays = int(expireddnsDays)
            break
        except:
            print('Invalid day option')
            pass

    logger.info("Days to keep dns logs: %i" % expireddnsDays)
    dnsexpiredSeconds = int(expireddnsDays) * 86400
    db.dns.ensure_index("timestamp",expireAfterSeconds=dnsexpiredSeconds)

    while True:
        expiredTempHours = raw_input("Enter number of hours to temporary event filters: [24] ")
        if len(expiredTempHours) == 0:
            expiredTempHours = 24
            break
        else:
            try:
                expiredTempHours = int(expiredTempHours)
                break
            except:
                print('Invalid Day option')
                pass

    logger.info("Hours to keep temporary Event Filters is %i" % expiredTempHours)
    expiredTempSeconds = expiredTempHours * 3600
    db.filters.ensure_index("temp_timestamp", expireAfterSeconds=expiredTempSeconds)

    while True:
        sessionMinutes = raw_input("Enter number of minutes until each console session times out: ")
        try:
            sessionMinutes = int(sessionMinutes)
            break
        except:
            print('Invalid minutes')
            pass
    logger.info("Session timeout %i minutes" % sessionMinutes)
    sessionTimeout = int(sessionMinutes) * 60
    db.sessions.ensure_index("last_accessed",expireAfterSeconds=sessionTimeout)

    if keep_db:
        while True:
            create_user = raw_input("Create user/reset password? [y/n]")
            if create_user == 'y' or create_user == 'Y' or create_user == 'n' or create_user == 'N':
                break
            else:
                print('Invalid option')
        if create_user == 'y' or create_user == 'Y':
            create_user = True
        else:
            create_user = False

    else:
        create_user = True

    session_salt = uuid.uuid4().hex
    if create_user:
        while True:
            user_name = raw_input("Enter username of admin user to create: ")
            if len(user_name) == 0:
                print('No username entered')
            elif len(user_name) < 4:
                print('User name is too short')
            else:
                break
        while True:
            print('Enter password: ')
            admin_pw = getpass.getpass()
            print('Re-enter password: ')
            admin_pw2 = getpass.getpass()
            if admin_pw == admin_pw2:
                break
            else:
                print("Passwords do not match")
        logger.info("Creating admin user %s" % user_name)
        password_salt = uuid.uuid4().hex
        admin_hashedPW = hashlib.sha512(str(admin_pw) + str(password_salt)).hexdigest()
        if len(list(db.users.find({"USERNAME": user_name }))) > 0:
            db.users.remove({"USERNAME": user_name})
        db.users.insert(
        {
                "USERNAME" : user_name,
                "user_admin" : "true",
                "ENABLED" : "true",
                "SALT": password_salt,
                "PASSWORD" : admin_hashedPW,
                "console" : "true",
                "date_modified" : datetime.datetime.utcnow(),
                "sensor_admin" : "true",
                "responder" : "true",
                "event_filters": "true",
                "server_admin" : "true",
                "date_created" : datetime.datetime.utcnow(),
                "PASSWORD_CHANGED": datetime.datetime.utcnow(),
        })

    config['Webserver'] = {}
    config['Webserver']['db'] = {}
    config['Webserver']['db']['url'] = ip
    config['Webserver']['db']['port'] = port
    config['Webserver']['db']['useAuth'] = useAuth
    if useAuth:
        config['Webserver']['db']['username'] = username
        if authType == 'X509':
            config['Webserver']['db']['auth_cert'] = auth_cert
            config['Webserver']['db']['auth_ca'] = auth_ca
        elif authType == 'Password':
            config['Webserver']['db']['password'] = password.encode('base64')
            config['Webserver']['db']['PW_Mechanism'] = PW_Mechanism
        config['Webserver']['db']['AuthType'] = authType
    #config['Webserver']['db']['SECRET_KEY'] = password_salt 
    config['Webserver']['db']['SESSION_KEY'] = session_salt
    config['Webserver']['web'] = {}
    config['Webserver']['web']['session_timeout'] = sessionMinutes
    config['Webserver']['events'] = {}
    config['Webserver']['events']['max_age'] = expiredDays
    config['Webserver']['events']['flow_max_age'] = expiredflowDays
    config['Webserver']['events']['dns_max_age'] = expireddnsDays
    config['Webserver']['events']['temp_filter_age'] = expiredTempHours
 
def setup_core():
    if os.path.exists('/usr/lib/python2.7/Minerva'):
        logger.info('Old Minerva python modules are removed')
        shutil.rmtree('/usr/lib/python2.7/Minerva')
    if os.path.exists('/usr/lib/python2.7/site-packages/Minerva'):
        logger.info('Old Minerva python modules are removed')
        shutil.rmtree('/usr/lib/python2.7/site-packages/Minerva')
    site_dists = [ 'CentOS Linux', 'redhat' ]
    if platform.linux_distribution()[0] in site_dists:
        shutil.copytree('Minerva','/usr/lib/python2.7/site-packages/Minerva')
    else:
        shutil.copytree('Minerva','/usr/lib/python2.7/Minerva')
    logger.info('Minerva python modules are installed')

def setup_server():
    print("**********************************************************")
    print("*               Setting up the web server                *")
    print("**********************************************************")
    logger.info("Setting up the web server")

    while True:
        hostname = raw_input("Enter hostname for webserver: ")
        if len(hostname) == 0:
            print('No hostname entered')
        else:
            break
    logger.info("Webserver hostname set to %s" % hostname)

    while True:
        bindIp = raw_input("Enter IP Address to bind to: ")
        if validate_ip(bindIp):
            break
        else:
            print('Invalid IP')
    logger.info("Webserver IP set to %s" % bindIp)

    while True:
        webport = raw_input("Enter Port for webserver to run on: [443] ")
        if len(webport) == 0:
            webport = 443
            break
        else:
            try:
                webport = int(webport)
                break
            except:
                print('Invalid port')
                pass
    logger.info("Webserver port set to %i" % int(webport))

    while True:
        threads = raw_input("Enter number of threads to respond to web requests: [8] ")
        if len(threads) == 0:
            threads = 8
            break
        else:
            try:
                threads = int(threads)
                break
            except:
                print('Invalid thread count')
                pass
    logger.info("Webserver threads set to %i" % int(threads))

    web_cert = raw_input("Enter full path of webcertificate to use (Will create one if none exists) [/var/lib/minerva/webserver/server.pem] ")
    if len(web_cert) == 0:
        web_cert = '/var/lib/minerva/webserver/server.pem'
        web_key = '/var/lib/minerva/webserver/private.pem'
    else:
        web_key = raw_input("Enter full path of web server's private key: ")
    logger.info("Web server cert set to %s" % web_cert)
    logger.info("Web server private key set to %s" % web_key)

    while True:
        password_tries = raw_input("Enter # of logon attempts before user is locked out: [3] ")
        if len(password_tries) == 0:
            password_tries = 3
            break
        else:
            try:
                password_tries = int(password_tries)
                break
            except:
                print('Invalid password try input')
                pass

    logger.info("Password failures set to %i" % int(password_tries))

    while True:
        password_min_length = raw_input("Enter minimum length for user passwords: [8] ")
        if len(password_min_length) == 0:
            password_min_length = 8
            break
        else: 
            try:
                password_min_length = int(password_min_length)
                break
            except:
                print('Invalid min length')
                pass
    logger.info("Min password length is set to %i" % int(password_min_length))

    while True:
        password_max_age = raw_input("Enter # of days a password is valid before needed to be changed: [90] ")
        if len(password_max_age) == 0:
            password_max_age = 90
            break
        else:
            try:
                password_max_age = int(password_max_age)
                break
            except:
                print('Invalid max length')
                pass
    logger.info("Max password age set to %i" % int(password_max_age))

    while True:
        pcap_timeout = raw_input("Enter # of seconds to wait on a pcap request: [300] ")
        if len(pcap_timeout) == 0:
            pcap_timeout = 300
            break
        else:
            try:
                pcap_timeout = int(pcap_timeout)
                break
            except:
                print('Invalid pcap timeout')
                pass
    logger.info("Pcap request timeout set to %i" % int(pcap_timeout))

    while True:
        maxResults = raw_input("Enter # of results to show in the console at a time: [5000] (15000 max) ")
        if len(maxResults) == 0:
            maxResults = 5000
            break
        else:
            try:
                maxResults = int(maxResults)
                if maxResults > 15000:
                    maxResults = 15000
                break
            except:
                print('Invalid max results input')
                pass
    logger.info("Max events set to %i" % int(maxResults))

    while True:
        lower_count = raw_input("Enter minimum # of lower case letters in a password: [2] ")
        if len(lower_count) == 0:
            lower_count = 2
            break
        else:
            try:
                lower_count = int(lower_count)
                break
            except:
                print('Invalid input')
                pass
    logger.info("Min password lower case set to %i" % int(lower_count))

    while True:
        upper_count = raw_input("Enter minimum # of upper case letters in a password: [2] ")
        if len(upper_count) == 0:
            upper_count = 2
            break
        else:
            try:
                upper_count = int(upper_count)
                break
            except:
                print('Invalid input')
                pass
    logger.info("Min password upper case set to %i" % int(upper_count))

    while True:
        digit_count = raw_input("Enter minimum # of numbers in a password: [2] ")
        if len(digit_count) == 0:
            digit_count = 2
            break
        else:
            try:
                digit_count = int(digit_count)
                break
            except:
                print('Invalid input')
                pass
    logger.info("Min numbers in a password set to %i" % int(digit_count))

    while True:
        special_count = raw_input("Enter minimum # of special characters in a password: [2] ")
        if len(special_count) == 0:
            special_count = 2
            break
        else:
            try:
                special_count = int(special_count)
                break
            except:
                print('Invalid Option')
                pass

    logger.info("Min numbers of special characters in password is %i" % int(special_count))

    config['Webserver']['web']['hostname'] = hostname
    config['Webserver']['web']['bindIp'] = bindIp
    config['Webserver']['web']['port'] = webport
    config['Webserver']['web']['threads'] = threads
    config['Webserver']['web']['certs'] = {}
    config['Webserver']['web']['certs']['webserver_cert'] = web_cert
    config['Webserver']['web']['certs']['webserver_key'] = web_key
    config['Webserver']['web']['pcap_timeout'] = pcap_timeout
    config['Webserver']['web']['password_requirements'] = {}
    config['Webserver']['web']['password_requirements']['password_tries'] = password_tries
    config['Webserver']['web']['password_requirements']['password_min_length'] = password_min_length
    config['Webserver']['web']['password_requirements']['password_max_age'] = password_max_age
    config['Webserver']['web']['password_requirements']['lower_count'] = lower_count
    config['Webserver']['web']['password_requirements']['upper_count'] = upper_count
    config['Webserver']['web']['password_requirements']['digit_count'] = digit_count
    config['Webserver']['web']['password_requirements']['special_count'] = special_count
    config['Webserver']['events']['maxResults'] = maxResults
    #os.makedirs(os.path.join(install_path,'bin/templates'))
    #os.makedirs(os.path.join(install_path,'bin/static'))

    logger.info("Copying over templates and static content")

    if os.path.exists(os.path.join(install_path,'bin/templates')):
        shutil.rmtree(os.path.join(install_path,'bin/templates'))
    shutil.copytree('templates',os.path.join(install_path,'bin/templates'))
    if os.path.exists(os.path.join(install_path,'bin/static')):
        shutil.rmtree(os.path.join(install_path,'bin/static'))
    shutil.copytree('static',os.path.join(install_path,'bin/static'))
    if os.path.exists(os.path.join(install_path,'bin/webserver.py')):
        os.remove(os.path.join(install_path,'bin/webserver.py'))
    shutil.copy('webserver.py',os.path.join(install_path,'bin/webserver.py'))

def setup_receiver():
    print("**********************************************************")
    print("*              Setting up the event receiver             *")
    print("**********************************************************")
    logger.info("Setting up the event receiver")
    listen_ips = {}
    print("**********************************************************")
    print("* The next IP and Port is what will listen for events    *")
    print("*   This is the combination that will be required for    *")
    print("*   setting up Agent Forwarders.                         *")
    print("**********************************************************")
    while True:
        while True:
            listen_ip = raw_input("Enter IP Address to listen on: ")
            if validate_ip(listen_ip):
                break
            else:
                print('Invalid IP')
        logger.info("Adding listener ip %s" % listen_ip)
        listen_ips[listen_ip] = {}
        listen_ips[listen_ip]['ports'] = []
        while True:
            while True:
                listen_port = raw_input("Enter port to listen on: ")
                try:
                    listen_port = int(listen_port)
                    break
                except:
                    print('Invalid Port')
                    pass
            logger.info("Adding listener port %i" % int(listen_port))
            listen_ips[listen_ip]['ports'].append(int(listen_port))
            while True:
                resp = raw_input("Do you want to add more ports? [y/n] ")
                if resp == 'y' or resp == 'Y' or resp == 'n' or resp == 'N':
                    break
                else:
                    print('Invalid Option')
            if resp == 'n' or resp == 'N':
                break
        listen_ips[listen_ip]['receive_threads'] = int(raw_input("How many threads do you want to process events? "))
        logger.info("Setting receive threads at %i" % listen_ips[listen_ip]['receive_threads'])
        while True:
            resp1 = raw_input("Do you want to add another IP? [y/n] ")
            if resp1 == 'y' or resp1 == 'Y' or resp1 == 'n' or resp1 == 'N':
                break
            else:
                print('Invalid option')
        if resp == 'n' or resp == 'N':
            break

    use_redis = 'yes'
    while True:
        event_key = raw_input("What Redis key do you want to use for events? [minerva-receiver] ")
        if len(event_key) == 0:
            event_key = 'minerva-receiver'
        break
    while True:
        filter_key = raw_input("What Redis key do you want to use for filters? [minerva-filters] ")
        if len(filter_key) == 0:
            filter_key = 'minerva-filters'
        break
    while True:
        filtercheck_key = raw_input("What Redis key do you want to use for filter management? [minerva-filters-check] ")
        if len(filtercheck_key) == 0:
            filtercheck_key = 'minerva-filters-check'
        break
    while True:
        watchlist_key = raw_input("What Redis key do you want to use for watchlists? [minerva-watchlist] ")
        if len(watchlist_key) == 0:
            watchlist_key = 'minerva-watchlist'
        break
    while True:
        watchcheck_key = raw_input("What Redis key do you want to use watchlist management? [minerva-watch-check] ")
        if len(watchcheck_key) == 0:
            watchcheck_key = 'minerva-watch-check'
        break

    while True:
        redis_server = raw_input("Enter redis host or ip: [127.0.0.1] ")
        if len(redis_server) == 0:
            redis_server = '127.0.0.1'
        break
    while True:
        redis_port = raw_input("Enter redis port: [6379] ")
        if len(redis_port) == 0:
            redis_port = 6379
            break
        else:
            try:
                redis_port = int(redis_port)
                break
            except:
                print('Bad Redis Port Number')

    while True:
        listener_timeout = raw_input("Enter number of seconds to timeout on a single receive thread: [20] ")
        if len(listener_timeout) == 0:
            listener_timeout = 20
            break
        else:
            try:
                listener_timeout = int(listener_timeout)
                break
            except:
                print('Invalid timeout')
                pass
    logger.info("Setting listener timeout at %i seconds" % int(listener_timeout))

    while True:
        ins_threads = raw_input("Enter number of processes you want to insert alerts: [4] ")
        if len(ins_threads) == 0:
            ins_threads = 4
            break
        else:
            try:
                ins_threads = int(ins_threads)
                break
            except:
                print('Invalid thread count')
                pass
    logger.info("Setting inserter threads to %i" % int(ins_threads))

    while True:
        ins_batch = raw_input("Enter max number of events to insert at a time: [500] ")
        if len(ins_batch) == 0:
            ins_batch = 500
            break
        else:
            try:
                ins_batch = int(ins_batch)
                break
            except:
                print('Invalid batch count')
                pass
    logger.info("Setting max events to insert to %i" % int(ins_batch))

    while True:
        ins_wait = raw_input("Enter max seconds to wait before inserting events: [20] ")
        if len(ins_wait) == 0:
            ins_wait = 20
            break
        else:
            try:
                ins_wait = int(ins_wait)
                break
            except:
                print('Invalid wait time')
                pass
    logger.info("Setting max seconds before inserting to %i seconds" % int(ins_wait))

    while True:
        filter_wait = raw_input("Enter number of seconds before reloading event filters: [3600] ")
        if len(filter_wait) == 0:
            filter_wait = 3600
            break
        else:
            try:
                filter_wait = int(filter_wait)
                break
            except:
                print('Invalid time')
                pass
    logger.info("Setting filter reload time to %i seconds" % int(filter_wait))

    rec_cert = raw_input("Enter full path of certificate to use (will create in this lcoation if it doenst exist): [/var/lib/minerva/receiver/server.pem] ")
    if len(rec_cert) == 0:
        rec_cert = '/var/lib/minerva/receiver/server.pem'
        rec_key = '/var/lib/minerva/receiver/private.pem'
    else:
        rec_key = raw_input("Enter full path of private key to use w/ the certificate above: ")
    logger.info("Certificate path set to %s" % rec_cert)
    logger.info("Private key path set to %s" % rec_key)

    print("***********************************************************")
    print("*  The next IP/port will be used to process pcap requests *")
    print("*    from the webserver.  This will only be used for      *")
    print("*    webserver communications                             *")
    print("***********************************************************")
    while True:
        pcap_ip = raw_input("Enter IP Address to listen for pcap requests from the webserver: ")
        if validate_ip(pcap_ip):
            break
        else:
            print('Invalid IP')
    logger.info("PCAP listening IP set to %s" % pcap_ip)

    while True:
        pcap_port = raw_input("Enter Port of Receiver to list for pcap requests for: [10009] ")
        if len(pcap_port) == 0:
            pcap_port = 10009
            break
        else:
            try:
                pcap_port = int(pcap_port)
                break
            except:
                print('Invalid port number')
                pass
    logger.info("PCAP listening port set to %i" % int(pcap_port))

    while True:
        pcap_threads = raw_input("Enter number of threads to process pcap requests: [4] ")
        if len(pcap_threads) == 0:
            pcap_threads = 4
            break
        else:
            try:
                pcap_threads = int(pcap_threads)
                break
            except:
                print('Invalid thread count')
                pass
    logger.info("Threads processing PCAP requests set to %i" % int(pcap_threads))

    while True:
        pcap_timeout = raw_input("Enter number of seconds to wait for a pcap request, Should be the same as webserver value: [300] ")
        if len(pcap_timeout) == 0:
            pcap_timeout = 300
            break
        else:
            try:
                pcap_timeout = int(pcap_timeout)
                break
            except:
                print('Invalid timeout')
                pass
    logger.info("PCAP Request timeout set to %i seconds" % int(pcap_timeout))

    config['Event_Receiver'] = {}
    config['Event_Receiver']['listen_ip'] = listen_ips
    config['Event_Receiver']['listener_timeout'] = listener_timeout
    config['Event_Receiver']['insertion_threads'] = int(ins_threads)
    config['Event_Receiver']['insertion_batch'] = int(ins_batch)
    config['Event_Receiver']['insertion_wait'] = int(ins_wait)
    config['Event_Receiver']['filter_wait'] = int(filter_wait)
    config['Event_Receiver']['redis'] = {}
    config['Event_Receiver']['redis']['enabled'] = use_redis
    config['Event_Receiver']['redis']['event_key'] = event_key
    config['Event_Receiver']['redis']['filter_key'] = filter_key
    config['Event_Receiver']['redis']['filtercheck_key'] = filtercheck_key
    config['Event_Receiver']['redis']['watchlist_key'] = watchlist_key
    config['Event_Receiver']['redis']['watchcheck_key'] = watchcheck_key
    config['Event_Receiver']['redis']['server'] = redis_server
    config['Event_Receiver']['redis']['port'] = redis_port
    config['Event_Receiver']['certs'] = {}
    config['Event_Receiver']['certs']['server_cert'] = rec_cert
    config['Event_Receiver']['certs']['private_key'] = rec_key
    config['Event_Receiver']['PCAP'] = {}
    config['Event_Receiver']['PCAP']['ip'] = pcap_ip
    config['Event_Receiver']['PCAP']['port'] = pcap_port
    config['Event_Receiver']['PCAP']['threads'] = pcap_threads
    config['Event_Receiver']['PCAP']['timeout'] = pcap_timeout
    shutil.copy('receiver.py',os.path.join(install_path,'bin'))

def setup_agent():
    print("**********************************************************")
    print("*                  Setting up the agent                  *")
    print("**********************************************************")
    logger.info("Setting up the agent")

    while True:
        sensor_name = raw_input("Enter name of sensor: ")
        if len(sensor_name) > 0:
            break
        else:
            print('No sensor name entered')
    logger.info("Sensor name set to %s" % sensor_name)

    client_cert = raw_input("Enter full pathname of sensor certificate (One will be created if it doesn't exist): [/var/lib/minerva/agent/agent.pem] ")
    if len(client_cert) == 0:
        client_cert = '/var/lib/minerva/agent/agent.pem'
        client_key = '/var/lib/minerva/agent/private.pem'
    else:
        client_key = raw_input("Enter full pathname of sensor private key for the certificate above: ")
    logger.info("Client certificate path set to %s" % client_cert)
    logger.info("Client private key path set to %s" % client_key)

    while True:
        use_redis = raw_input("Do you want to use Redis as your message broken (Recommended)? [y/n]")
        redis_mod = False
        if use_redis == 'y':
            try:
                import redis
                redis_mod = True
            except:
                print("Redis Chosen but missing python-redis module")
                logger.info("Redis Chosen but missing redis module")
                sys.exit()
            use_redis = 'yes'
            while True:
                redis_key = raw_input("What Redis key do you want to use? [minerva-agent] ")
                if len(redis_key) == 0:
                    redis_key = 'minerva-agent'
                break
            while True:
                redis_server = raw_input("Enter redis host or ip: [127.0.0.1] ")
                if len(redis_server) == 0:
                    redis_server = '127.0.0.1'
                break
            while True:
                redis_port = raw_input("Enter redis port: [6379] ")
                if len(redis_port) == 0:
                    redis_port = 6379
                    break
                else:
                    try:
                        redis_port = int(redis_port)
                        break
                    except:
                        print('Bad Redis Port Number')
            break
        else:
            use_redis = 'no'
            redis_key = ''   
            redis_server = ''
            redis_port = ''

    logfiles = {}
    while True:
        while True:
            ltype = raw_input("Enter alert type of log file: (suricata_eve, suricata-redis-channel, suricata-redis-list, snort_alert): ")
            if ltype in ['suricata-redis-channel','suricata-redis-list']:
                if use_redis == 'yes':
                    while True:
                        use_main_redis = raw_input("Same host (%s) and port (%i) information? [yes/no] " % (redis_server, redis_port))
                        if len(use_main_redis) == 0:
                            use_main_redis = 'yes'
                            break
                        elif use_main_redis in ['y','Y','yes','YES']:
                            use_main_redis = 'yes'
                            break
                        elif use_main_redis in ['n','N','no','NO']:
                            use_main_redis = 'no'
                            break
                        else:
                            print('Invalid option')
                else:
                    use_main_redis = 'no'
                    try:
                        import redis
                    except:
                        print("Redis Chosen but missing python-redis module")
                        logger.info("Redis Chosen but missing redis module")
                        sys.exit()

                if use_redis == 'no' or use_main_redis == 'no':
                    while True:
                        redis_server = raw_input("Enter redis host or ip: [127.0.0.1] ")
                        if len(redis_server) == 0:
                            redis_server = '127.0.0.1'
                        break
                    while True:
                        redis_port = raw_input("Enter redis port: [6379] ")
                        if len(redis_port) == 0:
                            redis_port = 6379
                            break
                        else:
                            try:
                                redis_port = int(redis_port)
                                break
                            except:
                                print('Bad Redis Port Number')
                while True:
                    redis_channel = raw_input("Enter Redis Channel or Key for Suricata: ")
                    if len(redis_channel) > 0:
                        break
                    else:
                        print("No Channel Entered")
                break
            elif ltype in ['suricata_eve', 'snort_alert']:
                while True:
                    lfile = raw_input("Enter full pathname of log file to send in: ")
                    if len(lfile) == 0:
                        print('No file entered')
                    elif not os.path.exists(lfile):
                        while True:
                            resp = raw_input("File %s does not exist, add it anyways? [y/n] " % lfile)
                            if resp == 'n' or resp == 'N' or resp == 'y' or resp == 'Y':
                                break
                        if resp == 'Y' or resp == 'y':
                            break
                    else:
                        break
                logger.info("Log file %s added" % lfile)
                break
            else:
                print('Invalid log type')
        logger.info("Log file type is %s" % ltype)
        logfiles[lfile] = {}
        logfiles[lfile]['type'] = ltype
        if ltype in ['suricata-redis-channel','suricata-redis-list']:
            logger.info("Redis channel is %s" % redis_channel)
            logfiles[lfile]['channel'] = redis_channel
            logfiles[lfile]['use_main'] = use_main_redis
            if use_main_redis == 'no':
                logfiles[lfile]['server'] = redis_server
                logfiles[lfile]['port'] = redis_port
        else:
            while True:
                pfile = raw_input("Enter full pathname of position file: ")
                if len(pfile) > 0:
                    break
                else:
                    print('No Position file entered')
            logger.info("Position file is set to %s" % pfile)

            logfiles[lfile]['position_file'] = pfile
        while True:
            resp = raw_input("Do you want to add more log files? [y/n] ")
            if resp == 'y' or resp == 'Y' or resp == 'n' or resp == 'N':
                break
            else:
                print('Invalid option')
        if resp == 'n' or resp == 'N':
            break

    server_cert = raw_input("Enter full pathname of where to save server cert: [/var/lib/minerva/agent/server.pem] ")
    if len(server_cert) == 0:
        server_cert = '/var/lib/minerva/agent/server.pem'
    logger.info("Path to store server cert is set to %s" % server_cert)

    print("*****************************************************************")
    print("* The Receiver IP And Port is where events will be forwarded to *")
    print("*****************************************************************")
    while True:
        destination = raw_input("Enter IP address of receiver to send to: ")
        if validate_ip(destination):
            break
        else:
            print('Invalid IP')
    logger.info("Receiver destination of %s set" % destination)

    while True:
        dest_port = raw_input("Enter destination port to send to: ")
        try:
            dest_port = int(dest_port)
            break
        except:
            print('Invalid Port')
    logger.info("Receiver port of %s set" % dest_port)

    while True:
        send_batch = raw_input("Enter max # of events to send at once: [500] ")
        if len(send_batch) == 0:
            send_batch = 500
            break
        else:
            try:
                send_batch = int(send_batch)
                break
            except:
                print('Invalid batch input')
                pass
    logger.info("Max events to send at once is set to %i" % int(send_batch))

    while True:
        send_wait = raw_input("Enter max # of seconds to wait to send events (Will send earlier if max events is reached): [10] ")
        if len(send_wait) == 0:
            send_wait = 10
            break
        else:
            try:
                send_wait = int(send_wait)
                break
            except:
                print('Invalid wait time')
                pass
    logger.info("Max wait time between sending events is set to %i" % int(send_wait))

    while True:
        fail_wait = raw_input("Enter max # of seconds to wait to send events after a failure: [10] ")
        if len(fail_wait) == 0:
            fail_wait = 10
            break
        else:
            try:
                fail_wait = int(fail_wait)
                break
            except:
                print('Invalid fail time')
                pass
    logger.info("Max fail time between sending events after a failure is set to %i" % int(fail_wait))





    print("**********************************************************")
    print("*          Configuring Agent PCAP Requests               *")
    print("**********************************************************")
    logger.info("Configuring Agent PCAP Requests")

    while True:
        max_packets = raw_input("Enter max # of packets to return per request: [10000] ")
        if len(max_packets) == 0:
            max_packets = 10000
            break
        else:
            try:
                max_packets = int(max_packets)
                break
            except:
                print('Invalid number')
                pass
    logger.info("Max packets to return per request is set to %i" % int(max_packets))

    while True:
        max_size = raw_input("Enter Max size(mb) of pcap files to return per reqeust: [20] ")
        if len(max_size) == 0:
            max_size = 20
            break
        else:
            try:
                max_size = int(max_size)
                break
            except:
                print('Invalid number entered')
                pass
    logger.info("Max size of pcap request is set to %i mb" % int(max_size))

    while True:
        max_files = raw_input("Enter Max # of pcap files to search through per request: [10] ")
        if len(max_files) == 0:
            max_files = 10
            break
        else:
            try:
                max_files = int(max_files)
                break
            except:
                print('Invalid number of files')
                pass
    logger.info("Max # of files to search through is set to %i" % int(max_files))

    while True:
        thres_time = raw_input("Enter max time in seconds past an event to grab packets for: [300] ")
        if len(thres_time) == 0:
            thres_time = 300
            break
        else:
            try:
                thres_time = int(thres_time)
                break
            except:
                print('Invalid seonds entered')
                pass
    logger.info("Max time window is set to %i seconds" % int(thres_time))

    prefix = raw_input("Enter prefix for pcap files: []")
    suffix = raw_input("Enter suffix for pcap files: [.pcap] ")
    if len(suffix) == 0:
        suffix = '.pcap'
    logger.info("PCAP Prefix is set to %s" % prefix)
    logger.info("PCAP suffix is set to %s" % suffix)

    while True:
        pcap_directory = raw_input("Enter complete path to base directory for pcap files: ")
        if len(pcap_directory) == 0:
            print('No directory entered')
            continue
        elif not os.path.exists(pcap_directory):
            print('Pcap directory does not exist')
            while True:
                resp = raw_input("Do you want to configure anyways? [y/n] ")
                if resp == 'y' or resp == 'Y' or resp == 'n' or resp == 'N':
                    break
                else:
                    print('Invalid option')
            if resp == 'y' or resp == 'Y':
                break
            else:
                continue
        break
    logger.info("PCAP storage directory is set to %s" % pcap_directory)

    while True:
        temp_directory = raw_input("Enter complete path of temp storage for pcap requests: ")
        if len(temp_directory) == 0:
            print('No temp directory entered')
            continue
        break
    logger.info("PCAP temp directory is set to %s" % pcap_directory)

    if not os.path.exists(temp_directory):
        logger.info("PCAP temp dir doesn't exist, creating it")
        os.makedirs(temp_directory)

    print("***************************************************************")
    print("*  This next IP and port is the what the agent will listen to *")
    print("*    for pcap requests from the receiver                      *")
    print("***************************************************************")
    while True:
        listener_ip = raw_input("Enter ip address to listen for requests on: ")
        if validate_ip(listener_ip):
            break
        else:
            print('Invalid IP Entered')
    logger.info("PCAP Listener bound to %s" % listener_ip)

    while True:
        listener_port = raw_input("Enter port to listen for requests on: [10010] ")
        if len(listener_port) == 0:
            listener_port = 10010
            break
        else:
            try:
                listener_port = int(listener_port)
                break
            except:
                print('Invalid port')
                pass
    logger.info("PCAP Listener port set to %i" % int(listener_port))

    while True:
        listener_threads = raw_input("Enter number of threads to process requests: [4] ")
        if len(listener_threads) == 0:
            listener_threads = 4
            break
        else:
            try:
                listener_threads = int(listener_threads)
                break
            except:
                print('Invalid Thread count')
                pass
    logger.info("PCAP Processing threads set to %i" % int(listener_threads))

    config['Agent_forwarder'] = {}
    config['Agent_forwarder']['sensor_name'] = sensor_name
    config['Agent_forwarder']['client_cert'] = client_cert
    config['Agent_forwarder']['client_private'] = client_key
    config['Agent_forwarder']['redis'] = {}
    config['Agent_forwarder']['redis']['enabled'] = use_redis
    config['Agent_forwarder']['redis']['key'] = redis_key
    config['Agent_forwarder']['redis']['server'] = redis_server
    config['Agent_forwarder']['redis']['port'] = redis_port
    config['Agent_forwarder']['logfiles'] = logfiles
    config['Agent_forwarder']['target_addr'] = {}
    config['Agent_forwarder']['target_addr']['server_cert'] = server_cert
    config['Agent_forwarder']['target_addr']['destination'] = destination
    config['Agent_forwarder']['target_addr']['port'] = int(dest_port)
    config['Agent_forwarder']['target_addr']['send_batch'] = int(send_batch)
    config['Agent_forwarder']['target_addr']['send_wait'] = int(send_wait)
    config['Agent_forwarder']['target_addr']['fail_wait'] = int(fail_wait)
    config['Agent_forwarder']['pcap'] = {}
    config['Agent_forwarder']['pcap']['max_packets'] = max_packets
    config['Agent_forwarder']['pcap']['max_size'] = max_size
    config['Agent_forwarder']['pcap']['max_files'] = max_files
    config['Agent_forwarder']['pcap']['thres_time'] = thres_time
    config['Agent_forwarder']['pcap']['prefix'] = prefix
    config['Agent_forwarder']['pcap']['suffix'] = suffix
    config['Agent_forwarder']['pcap']['pcap_directory'] = pcap_directory
    config['Agent_forwarder']['pcap']['temp_directory'] = temp_directory
    config['Agent_forwarder']['listener'] = {}
    config['Agent_forwarder']['listener']['ip'] = listener_ip
    config['Agent_forwarder']['listener']['port'] = listener_port
    config['Agent_forwarder']['listener']['threads'] = listener_threads
    shutil.copy('agent.py',os.path.join(install_path,'bin'))

def write_config():
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader('templates'))
    tmp = env.get_template('minerva.jinja')
    conf_file = open(os.path.join(install_path,'etc/minerva.yaml'),'w')
    conf_write = tmp.render(config)
    conf_file.writelines(tmp.render({ "config": config }))
    conf_file.close()

def choose_db():
    while True:
        print("\n**************************************************************************")
        print('* Only use if you have an already configured minerva database in mongodb *')
        print("**************************************************************************")
        resp = raw_input('Connect to existing minerva database? [y/n] ')
        if resp == 'y' or resp == 'Y' or resp == 'n' or resp == 'N':
            break
        else:
            print('Invalid option')
    if resp == 'y' or resp == 'Y':
        setup_db_lite()
    else:
        setup_db()


def main():
    global config, install_path, logger
    logging.basicConfig(format='%(asctime)s: %(message)s',filename='setup.log', level=logging.DEBUG)
    logger = logging.getLogger()
    logger.info('********************************************************************************************************')
    logger.info('Starting Minerva Setup')
    config = {}
    while(True):
        print("**********************************************************")
        print("*                    Minerva-IDS Setup                   *")
        print("*                                                        *")
        print("* Please choose an install method:                       *")
        print("*    1. StandAlone (Server, Agent and Receiver)          *")
        print("*    2. Server/Receiver                                  *")
        print("*    3. WebServer only                                   *")
        print("*    4. Receiver Only                                    *")
        print("*    5. Agent Only                                       *")
        print("*    6. Database Only                                    *")
        print("**********************************************************")
        install_type = raw_input('*> ')
        if int(install_type) >= 1 and int(install_type) < 7:
            logger.info('Choosing install option %i' % int(install_type))
            break
        else:
            print('Invalid Option')
            logger.error('Invalid option %s' % install_type)
    location = raw_input("Enter installation Directory: [/opt/minerva] ")
    if len(location) == 0:
        location = '/opt/minerva'
    logger.info('Installation Directory is %s' % location)
    if os.path.exists(location):
        if os.path.exists(os.path.join(location,'/etc/minerva.yaml')):
            logger.info('%s exists' % location)
            resp = raw_input("Previous Installation Detected, Install over it? [y/n]")
            if resp == 'y' or resp == 'Y':
                install_path = location
                if not os.path.exists(location):
                    os.makedirs(location)
                if not os.path.exists(os.path.join(location,'bin')):
                    os.makedirs(os.path.join(location,'bin'))
                if not os.path.exists(os.path.join(location,'etc')):
                    os.makedirs(os.path.join(location,'etc'))
            else:
                print("Choose a new location and start again")
                sys.exit()
            logger.warning('Write installtion option chosen is %s' % resp )
        else:
            install_path = location
            logger.info('Installing in to %s' % install_path)
            if not os.path.exists(os.path.join(install_path,'bin')):
                os.makedirs(os.path.join(install_path,'bin'))
            if not os.path.exists(os.path.join(install_path, 'etc')):
                os.makedirs(os.path.join(install_path,'etc'))
    else:
        try:
            os.makedirs(location)
            os.makedirs(os.path.join(location,'bin'))
            os.makedirs(os.path.join(location,'etc'))
            install_path = location
            logger.info('Installing in to %s' % install_path)
        except:
            print("Unable to make directory %s, check permissions and try again" % location)
            logger.error("Unable to make directory %s, check permissions and try again" % location)
            sys.exit()
    if int(install_type) == 1:
        check_server()
        check_agent()
        check_receiver()
        choose_db()
        setup_server()
        setup_core()
        setup_receiver()
        setup_agent()
    elif int(install_type) == 2:
        check_server()
        check_receiver()
        choose_db()
        setup_server()
        setup_core()
        setup_receiver()
    elif int(install_type) == 3:
        check_server()
        choose_db()
        setup_server()
        setup_core()
    elif int(install_type) == 4:
        check_receiver()
        choose_db()
        setup_core()
        setup_receiver()
    elif int(install_type) == 5:
        check_agent()
        setup_core()
        setup_agent()
    logger.info('Writing Config to disk')
    write_config()
    logger.info('********************************************************************************************************')
main()
