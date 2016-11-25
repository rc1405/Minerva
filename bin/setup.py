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

def check_core():
    try:
        import M2Crypto
        logger.error('%s is installed' % 'M2Crypto')
    except:
        print('M2Crypto not installed')
        logger.error('M2Crypto not installed')
        sys.exit()
    try:
        import zmq
        logger.info('%s is installed' % 'pytz')
    except:
        print('pytz not installed')
        logger.error('pytz not installed')
        sys.exit()
    try:
        import yaml
        logger.info('%s is installed' % 'pyyaml')
    except:
        print('PyYAmL not installed')
        logger.error('PyYAmL not installed')
        sys.exit()
    try:
        import pytz
        logger.info('%s is installed' % 'pytz')
    except:
        print('pytz not installed')
        logger.error('pytz not installed')
        sys.exit()

def check_server():
    try:
        import pymongo
        logger.info('%s is installed' % 'pymongo')
    except:
        print('Pymongo not installed')
        logger.info('Pymongo not installed')
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
        import dateutil
        logger.info('%s is installed' % 'dateutil')
    except:
        print('python-dateutil not installed')
        logger.error('python-dateutil not installed')
        sys.exit()

def check_receiver():
    try:
        import pymongo
        logger.info('%s is installed' % 'pymongo')
    except:
        print('Pymongo not installed')
        logger.error('Pymongo not installed')
        sys.exit()
    try:
        import yara
        logger.info('%s is installed' % 'yara-python')
    except:
        print('yara-pyhon not installed')
        logger.error('yara-python not installed')
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

def map_indexes(ind):
    return ind['name']

def setup_db_new(lite=False):
    INDEX_VER = 101
    import pymongo
    print("IMPORTANT: If using a sharded cluster, shard keys must be setup before running this script")
    print("Setting Up Receiver DB connection")
    logger.info("Setting Up Receiver DB connection")
    
    while True:
        ip = raw_input('Please enter database IP or mongodb connection string: [127.0.0.1] ')
        if len(ip) == 0:
            ip = '127.0.0.1'
        break
    logger.info("DB Connection string set to %s" % ip)

    while True:
        use_port = raw_input('Would you like to specify a port? [Y/N] Select N to use connection string only ')
        if use_port[:1].lower() == 'y':
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
            break
        elif use_port[:1].lower() == 'n':
            port = 0
            logger.info("No port specified")
            break
        else:
            print("invalid selection")

    while True:
        useSSL = raw_input('Use SSL to connect to the DB? [Y/N]')
        if len(useSSL) == 0:
            print("No input detected")
            continue
        if useSSL[:1].lower() == 'y':
            while True:
                ssl_certfile = raw_input('Specify the cert file to use: ')
                if len(ssl_certfile) == 0 or not os.path.exists(ssl_certfile):
                    print("Error: Cert file does not exist")
                    continue 
                break
            while True:
                ssl_ca_certs = raw_input('Specify the CACerts file to use: ')
                if len(ssl_ca_certs) == 0 or not os.path.exists(ssl_ca_certs):
                    print("Error: Cert file does not exist")
                    continue
                break
            break
        elif useSSL[:1].lower() == 'n':
            break
        else:
            print("Invalid selection")

    while True:
        useAuth = raw_input('Use db authentication? Y/N [N] ')
        if useAuth.lower() == 'y' or use_auth.lower() == 'n' or len(use_auth) == 0:
            break
        else:
            print('Invalid db auth option')
    logger.info('Use DB Auth is set to %s' % useAuth)
    if useAuth.lower() == 'y':
        while True:
            print("Pick an Authentication Type\n\t1) Username/Password\n\t2) X509")
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
        if authType == 'X509':
            while True:
                cert_string = raw_input("Enter a x509 Subject: ")
                if len(cert_string) > 0:
                    break
                else:
                    print('No subject selected')
            logger.info('Cert subject submitted is %s' % cert_string)

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
            try:
                if int(port) == 0:
                    conn_str = ip
                else:
                    conn_str = "%s:%i" % (ip, int(port))
                client = pymongo.MongoClient(conn_str,
                                             ssl=True,
                                             ssl_certfile=auth_cert,
                                             ssl_cert_reqs=ssl.CERT_REQUIRED,
                                             ssl_ca_certs=ssl_ca_certs)
                client.minerva.authenticate(cert_string, mechanism='MONGODB-X509')
            except:
                print("Unable to connect to DB")
                logger.error("Unable to connect to DB")
                sys.exit()
        elif authType == 'Password':
            while True:
                username = raw_input("Enter a username: ")
                if len(username) > 0:
                    break
                else:
                    print('No username selected')
            logger.info('DB Username chosen is %s' % username)

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

    if not lite:
        db = client.minerva
        collections = db.collection_names()
        logger.info("Creating collections if they do not exist")
        if not 'alerts' in collections:
            db.create_collection('alerts')
        if not 'filters' in collections:
            db.create_collection('filters')
        if not 'flow' in collections:
            db.create_collection('flow')
        if not 'dns' in collections:
            db.create_collection('dns')
        if not 'certs' in collections:
            db.create_collection('certs')
        if not 'watchlist' in collections:
            db.create_collection('watchlist')
        if not 'signatures' in collections:
            db.create_collection('signatures')
        if not 'sessions' in collections:
            db.create_collection('sessions')
        if not 'keys' in collections:
            db.create_collection('keys')
        if not 'users' in collections:
            db.create_collection('users')
            create_user = True
        else:
            create_user = False

        alert_indexes = map(map_indexes, db.alerts.list_indexes())
        for i in alert_indexes:
            if i == 'timestamp_1' or i[:12] == 'alert-search' or i[:13] == 'alert-expired':
                db.alerts.drop_index(i)

        logger.info("Alert search index created is: %s" % '([("MINERVA_STATUS", pymongo.ASCENDING),("timestamp", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("alert.signature", pymongo.ASCENDING),("alert.category", pymongo.ASCENDING),("alert.signature_id", pymongo.ASCENDING),("alert.rev", pymongo.ASCENDING),("alert.gid", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="alert-search-index")')

        db.alerts.create_index([("MINERVA_STATUS", pymongo.ASCENDING),("timestamp", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("alert.signature", pymongo.ASCENDING),("alert.category", pymongo.ASCENDING),("alert.signature_id", pymongo.ASCENDING),("alert.rev", pymongo.ASCENDING),("alert.gid", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="alert-search-%i" % INDEX_VER)

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
        db.alerts.ensure_index("timestamp",name="alert-expired-%i" % INDEX_VER, expireAfterSeconds=expiredSeconds)


        flow_indexes = map(map_indexes, db.flow.list_indexes())
        for i in flow_indexes:
            if i == 'timestamp_1' or i[:11] == 'flow-search' or i[:12] == 'flow-expired':
                db.flow.drop_index(i)

        logger.info("Flow search index created is: %s " % '([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("netflow.start", pymongo.ASCENDING),("netflow.end", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="flow-search-index")')

        db.flow.create_index([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("netflow.start", pymongo.ASCENDING),("netflow.end", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="flow-search-%i" % INDEX_VER)

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
        db.flow.ensure_index("timestamp",name="flow-expired-%i" % INDEX_VER,expireAfterSeconds=flowexpiredSeconds)

        dns_indexes = map(map_indexes, db.dns.list_indexes())
        for i in dns_indexes:
            if i == 'timestamp_1' or i[:10] == 'dns-search' or i[:11] == 'dns-expired':
                db.dns.drop_index(i)

        logger.info("DNS search index created is: %s " % '([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("timestamp", pymongo.ASCENDING),("sensor", pymongo.ASCENDING),("dns.type", pymongo.ASCENDING),("dns.rrtype", pymongo.ASCENDING),("dns.rcode", pymongo.ASCENDING),("dns.rrname", pymongo.ASCENDING),("dns.rdata", pymongo.ASCENDING)],name="dns-search-index")')

        db.dns.create_index([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("timestamp", pymongo.ASCENDING),("sensor", pymongo.ASCENDING),("dns.type", pymongo.ASCENDING),("dns.rrtype", pymongo.ASCENDING),("dns.rcode", pymongo.ASCENDING),("dns.rrname", pymongo.ASCENDING),("dns.rdata", pymongo.ASCENDING)],name="dns-search-%i" % INDEX_VER)

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
        db.dns.ensure_index("timestamp",name="dns-expired-%i" % INDEX_VER, expireAfterSeconds=dnsexpiredSeconds)

        filters_indexes = map(map_indexes, db.filters.list_indexes())
        for i in filters_indexes:
            if i == 'temp_timestamp_1' or i[:12] == 'temp-expired':
                db.filters.drop_index(i)

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
        db.filters.ensure_index("temp_timestamp", name="temp-expired-%i" % INDEX_VER, expireAfterSeconds=expiredTempSeconds)

        session_indexes = map(map_indexes, db.sessions.list_indexes())
        for i in session_indexes:
            if i == 'last_accessed_1' or i[:15] == 'session-expired':
                db.sessions.drop_index(i)

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
        db.sessions.ensure_index("last_accessed",name="session-expired-%i" % INDEX_VER, expireAfterSeconds=sessionTimeout)

        key_indexes = map(map_indexes, db.keys.list_indexes())
        for i in key_indexes:
            if i == 'timestamp_1' or i[:11] == 'key-expired':
                db.keys.drop_index(i)
        db.keys.ensure_index("timestamp",name="key-expired-%i" % INDEX_VER,expireAfterSeconds=3600)

        if not create_user:
            while True:
                create_user = raw_input("Create user/reset password? [y/n]")
                if create_user == 'y' or create_user == 'Y' or create_user == 'n' or create_user == 'N':
                    break
                else:
                    print('Invalid option')

        session_salt = uuid.uuid4().hex
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
    else:
        while True:
            sessionMinutes = raw_input("Enter number of minutes until each console session times out: ")
            try:
                sessionMinutes = int(sessionMinutes)
                break
            except:
                print('Invalid minutes')
                pass
        logger.info("Session timeout %i minutes" % sessionMinutes)

    config['Database'] = {}
    config['Database']['db'] = {}
    config['Database']['db']['url'] = ip
    config['Database']['db']['port'] = port
    config['Database']['db']['useAuth'] = useAuth

    if useSSL[:1].lower() == 'y':
        config['Database']['db']['useSSL'] = True
        config['Database']['db']['ssl_certfile'] = ssl_certfile
        config['Database']['db']['ssl_ca_certs'] = ssl_ca_certs
    else:
        config['Database']['db']['useSSL'] = False

    if useAuth:
        if authType == 'X509':
            config['Database']['db']['x509Subject'] = cert_string
            config['Database']['db']['auth_cert'] = auth_cert
        elif authType == 'Password':
            config['Database']['db']['username'] = username
            config['Database']['db']['password'] = password
            config['Database']['db']['PW_Mechanism'] = PW_Mechanism
        config['Database']['db']['AuthType'] = authType
    config['Database']['web'] = {}
    config['Database']['web']['session_timeout'] = sessionMinutes
    config['Database']['events'] = {}

    if not lite:
        config['Database']['db']['SESSION_KEY'] = session_salt
        config['Database']['events']['max_age'] = expiredDays
        config['Database']['events']['flow_max_age'] = expiredflowDays
        config['Database']['events']['dns_max_age'] = expireddnsDays
        config['Database']['events']['temp_filter_age'] = expiredTempHours

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
    print("**********************************************************")
    print("                Setting Up Logger                        *")
    print("**********************************************************")
    logger.info("Setting up the logger")
    while True:
        print("**********************************************************")
        print("  Choose Logging Level:                                  *")
        print("     1)  Normal  - Default                               *")
        print("     2)  Debug                                           *")
        print("**********************************************************")
        log_level = raw_input("> ")
        if len(log_level) == 0:
            log_level = 'INFO'
            break
        else:
            try:
                if int(log_level) == 1:
                    log_level = 'INFO'
                    break
                elif int(log_level) == 2:
                    log_level = 'DEBUG'
                    break
                else:
                    print("Invalid Option")
            except:
                print("Invalid Option")
    logger.info("Log level set to %s" % log_level)
    config['Logger'] = {}
    config['Logger']['level'] = log_level
    while True:
        print("**********************************************************")
        print("  Choose Logging directory:                              *")
        print("**********************************************************")
        log_directory = raw_input("> ")
        if not os.path.exists(log_directory):
            log_cont = raw_input("Path does not exist.  Add anyways? [Y/N] ")
            if log_cont.upper() == 'Y':
                break
            elif log_cont.upper() == 'N':
                continue
            else:
                print('Invalid Option')
                continue
        break
    logger.info("Log directory set to %s" % log_directory)
    config['Logger']['directory'] = log_directory
    while True:
        log_count = raw_input("Enter number of logs to retain: [2] ")
        try:
            if len(log_count) == 0:
                log_count = 2
            else:
                log_count = int(log_count)
            break
        except:
            print("Invalid selection")
    logger.info("Log retention is %i" % log_count)
    config['Logger']['count'] = log_count
    while True:
        log_size = raw_input("Enter size of logs in MB: [20] ")
        try:
            if len(log_size) == 0:
                log_size = 1024 * 1024 * 1024 * 20
            else:
                log_size = int(log_count) * 1024 * 1024 * 1024 
            break
        except:
            print("Invalid selection")
    logger.info("Log size set to %i bytes" % log_size)
    config['Logger']['size'] = log_size

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

    if not 'Webserver' in config.keys():
        config['Webserver'] = {}
        config['Webserver']['web'] = {}
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
    print("* The next IP and Ports are for received events and      *")
    print("*   requesting PCAP. These combinations will be required *")
    print("*   for setting up Agent Forwarders.                     *")
    print("**********************************************************")
    while True:
        while True:
            listen_ip = raw_input("Enter IP Address to listen on: ")
            if validate_ip(listen_ip):
                break
            else:
                print('Invalid IP')
        logger.info("Adding ip %s" % listen_ip)
        listen_ips[listen_ip] = {}
        listen_ips[listen_ip]['recv_ports'] = []
        while True:
            while True:
                pub_port = raw_input("Enter port to publish requests on: ")
                try:
                    pub_port = int(pub_port)
                    break
                except:
                    print('Invalid Port')
                    pass
            logger.info("Adding pub port %i" % pub_port)
            listen_ips[listen_ip]['pub_port'] = pub_port
            while True:
                listen_port = raw_input("Enter port to listen on: ")
                try:
                    listen_port = int(listen_port)
                    break
                except:
                    print('Invalid Port')
                    pass
            logger.info("Adding recv port %i" % int(listen_port))
            listen_ips[listen_ip]['recv_ports'].append(int(listen_port))
            while True:
                resp = raw_input("Do you want to add more ports? [y/n] ")
                if resp == 'y' or resp == 'Y' or resp == 'n' or resp == 'N':
                    break
                else:
                    print('Invalid Option')
            if resp == 'n' or resp == 'N':
                break
        while True:
            resp1 = raw_input("Do you want to add another IP? [y/n] ")
            if resp1 == 'y' or resp1 == 'Y' or resp1 == 'n' or resp1 == 'N':
                break
            else:
                print('Invalid option')
        if resp == 'n' or resp == 'N':
            break

    while True:
        ins_threads = raw_input("Enter number of worker processes: [4] ")
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
        filter_wait = raw_input("Enter number of seconds before reloading event filters and watchlist: [3600] ")
        if len(filter_wait) == 0:
            filter_wait = 3600
            break
        else:
            try:
                filter_wait = int(filter_wait)
                break
            except:
                print('Invalid entry')
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

    config['Event_Receiver'] = {}
    config['Event_Receiver']['listen_ip'] = listen_ips
    config['Event_Receiver']['worker_threads'] = int(ins_threads)
    config['Event_Receiver']['watchlist_update'] = int(filter_wait)
    config['Event_Receiver']['certs'] = {}
    config['Event_Receiver']['certs']['server_cert'] = rec_cert
    config['Event_Receiver']['certs']['private_key'] = rec_key
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

    logfiles = {}
    while True:
        while True:
            ltype = raw_input("Enter alert type of log file: (suricata_eve, suricata-redis-list, snort_alert): ")
            if ltype == 'suricata-redis-list':
                try:
                    import redis
                except:
                    print("Redis Chosen but missing python-redis module")
                    logger.info("Redis Chosen but missing redis module")
                    sys.exit()

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
                    redis_channel = raw_input("Enter Redis Key for Suricata: ")
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
        if ltype == 'suricata-redis-list':
            logger.info("Redis channel is %s" % redis_channel)
            logfiles[lfile]['channel'] = redis_channel
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
    print("*   and where the agent will listen for PCAP requests           *")
    print("*****************************************************************")
    receivers = {}
    while True:
        while True:
            destination = raw_input("Enter IP address of receiver to send to: ")
            if validate_ip(destination):
                break
            else:
                print('Invalid IP')
        logger.info("Receiver destination of %s added" % destination)
        receivers[destination] = {}
        receivers[destination]['pub_ports'] = []

        while True:
            while True:
                dest_port = raw_input("Enter destination port to send to: ")
                try:
                    dest_port = int(dest_port)
                    break
                except:
                    print('Invalid Port')
            logger.info("Receiver port of %s added" % dest_port)
            receivers[destination]['pub_ports'].append(dest_port)
            more_ports = raw_input("Would you like to add more ports? [Y/N]")
            if more_ports.upper() == 'N':
                break

        while True:
            sub_port = raw_input("Enter receiver port to listen for requests: ")
            try:
                sub_port = int(sub_port)
                break
            except:
                print('Invalid Port')
        logger.info("Sub port of %s added" % sub_port)
        receivers[destination]['sub_port'] = sub_port

        more_dest = raw_input("Would you like to add more receivers? [Y/N]")
        if more_dest.upper() == 'N':
            break    

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
    config['Agent_forwarder']['logfiles'] = logfiles
    config['Agent_forwarder']['destinations'] = receivers
    config['Agent_forwarder']['send_batch'] = int(send_batch)
    config['Agent_forwarder']['send_wait'] = int(send_wait)
    config['Agent_forwarder']['fail_wait'] = int(fail_wait)
    config['Agent_forwarder']['pcap'] = {}
    config['Agent_forwarder']['pcap']['max_packets'] = max_packets
    config['Agent_forwarder']['pcap']['max_size'] = max_size
    config['Agent_forwarder']['pcap']['max_files'] = max_files
    config['Agent_forwarder']['pcap']['thres_time'] = thres_time
    config['Agent_forwarder']['pcap']['prefix'] = prefix
    config['Agent_forwarder']['pcap']['suffix'] = suffix
    config['Agent_forwarder']['pcap']['pcap_directory'] = pcap_directory
    config['Agent_forwarder']['pcap']['temp_directory'] = temp_directory
    config['Agent_forwarder']['worker_threads'] = listener_threads
    shutil.copy('agent.py',os.path.join(install_path,'bin'))

def write_config():
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader('templates'))
    tmp = env.get_template('minerva.jinja')
    conf_file = open(os.path.join(install_path,'etc/minerva.yaml'),'w')
    conf_file.writelines(tmp.render({ "config": config }))
    conf_file.close()

def choose_db():
    while True:
        print("\n**************************************************************************")
        print('* Only use if you have an already configured minerva database in mongodb *')
        print('*    Such as connecting a receiver to an existing setup                  *')
        print("**************************************************************************")
        resp = raw_input('Connect to existing minerva database? [y/n] ')
        if resp == 'y' or resp == 'Y' or resp == 'n' or resp == 'N':
            break
        else:
            print('Invalid option')
    if resp == 'y' or resp == 'Y':
        setup_db_new(lite=True)
    else:
        setup_db_new()


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
    
    check_core()
    if int(install_type) == 1:
        check_server()
        check_receiver()
        choose_db()
        setup_server()
        setup_receiver()
        setup_agent()
    elif int(install_type) == 2:
        check_server()
        check_receiver()
        choose_db()
        setup_server()
        setup_receiver()
    elif int(install_type) == 3:
        check_server()
        choose_db()
        setup_server()
    elif int(install_type) == 4:
        check_receiver()
        choose_db()
        setup_receiver()
    elif int(install_type) == 5:
        setup_agent()
    elif int(install_type) == 6:
        choose_db()
        setup_server()
    setup_core()

    logger.info('Writing Config to disk')
    write_config()
    logger.info('********************************************************************************************************')
main()
