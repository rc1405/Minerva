import logging
import os
import sys
import ssl
import copy
import datetime
import time
import shutil
import getpass

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
    try:
        import bcrypt
        logger.info('%s is installed' % 'bcrypt')
    except:
        print('bcrypt is not installed')
        logger.error('bcrypt is not installed')
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

def setup_db_lite():
    import pymongo
    import bcrypt
    print("Setting Up Receiver DB connection")
    logger.info("Setting Up Receiver DB connection")
    
    ip = raw_input('Please enter database ip: [127.0.0.1] ')
    if len(ip) == 0:
        ip = '127.0.0.1'
    logger.info("DB Ip is set to %s" % ip)

    port = raw_input('Please enter database port: [27017] ')
    if len(port) == 0:
        port = 27017
    logger.info("DB Port is set to %i" % int(port))

    useAuth = raw_input('Use db authentication? Y/N [N] ')
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
        username = raw_input("Enter a username: ")
        logger.info('DB Username chosen is %s' % username)
        if authType == 'X509':
            auth_cert = raw_input("Enter full path to cert used for authentication: ")
            logger.info('Auth Cert path is %s' % auth_cert)
            auth_ca = raw_input("Enter full path to ca_certs to be used: ")
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

def setup_db():
    import pymongo
    import bcrypt
    print("Setting up the Database")
    logger.info("Setting up the Database")
    ip = raw_input('Please enter database ip: [127.0.0.1] ')
    if len(ip) == 0:
        ip = '127.0.0.1'
    logger.info('Database IP is %s' % ip)
    port = raw_input('Please enter database port: [27017] ')
    if len(port) == 0:
        port = 27017
    logger.info('Database Port is %i' % int(port))
    print("****IF AUTHENTICATION METHOD IS CHOSEN, IT MUST BE SETUP PRIOR TO RUNNING SETUP*****")
    useAuth = raw_input('Use db authentication? Y/N [N] ')
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
        username = raw_input("Enter a username: ")
        logger.info('DB Username chosen is %s' % username)
        if authType == 'X509':
            auth_cert = raw_input("Enter full path to cert used for authentication: ")
            logger.info('Auth Cert path is %s' % auth_cert)
            auth_ca = raw_input("Enter full path to ca_certs to be used: ")
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
        resp = raw_input('Database already exists, do you want to keep it? [N]')
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
    if not 'flow' in collections:
        db.create_collection('flow')
    else:
        db.flow.drop_indexes()
    if not 'sessions' in collections:
        db.create_collection('sessions')
    else:
        db.sessions.drop_indexes()
    if not 'users' in collections:
        db.create_collection('users')
   
    #db.alerts.create_index([("MINERVA_STATUS", pymongo.ASCENDING),("epoch", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("alert.signature", pymongo.TEXT),("alert.category", pymongo.TEXT),("alert.signature_id", pymongo.ASCENDING),("alert.rev", pymongo.ASCENDING),("alert.gid", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="alert-search-index")

    logger.info("Alert search index created is: %s" % '([("MINERVA_STATUS", pymongo.ASCENDING),("epoch", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("alert.signature", pymongo.ASCENDING),("alert.category", pymongo.ASCENDING),("alert.signature_id", pymongo.ASCENDING),("alert.rev", pymongo.ASCENDING),("alert.gid", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="alert-search-index")')

    db.alerts.create_index([("MINERVA_STATUS", pymongo.ASCENDING),("epoch", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("alert.signature", pymongo.ASCENDING),("alert.category", pymongo.ASCENDING),("alert.signature_id", pymongo.ASCENDING),("alert.rev", pymongo.ASCENDING),("alert.gid", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)],name="alert-search-index")

    expiredDays = raw_input("Enter number of days to keep alerts: ")
    logger.info("Days to keep alerts %s" % expiredDays)
    expiredSeconds = int(expiredDays) * 86400
    db.alerts.ensure_index("timestamp",expireAfterSeconds=expiredSeconds)

    logger.info("Flow search index created is: %s " % '([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("netflow.start_epoch", pymongo.ASCENDING),("netflow.stop_epoch", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)])')

    db.flow.create_index([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING),("netflow.start_epoch", pymongo.ASCENDING),("netflow.stop_epoch", pymongo.ASCENDING),("sensor", pymongo.ASCENDING)])

    expiredflowDays = raw_input("Enter number of days to keep flow data: ")
    logger.info("Days to keep flow data %s" % expiredflowDays)
    flowexpiredSeconds = int(expiredflowDays) * 86400
    db.flow.ensure_index("timestamp",expireAfterSeconds=flowexpiredSeconds)

    sessionMinutes = raw_input("Enter number of minutes until each console session times out: ")
    logger.info("Session timeout %s minutes" % sessionMinutes)
    sessionTimeout = int(sessionMinutes) * 60
    db.sessions.ensure_index("last_accessed",expireAfterSeconds=sessionTimeout)

    if keep_db:
        create_user = raw_input("Create user/reset password? [y/n]")
        if create_user == 'y' or create_user == 'Y':
            create_user = True
        else:
            create_user = False
        password_salt = raw_input("Enter previous Password Salt Value or hit enter if you don't know it: ")
        if len(password_salt) == 0:
            print("All user passwords will need to be reset")
            password_salt = bcrypt.gensalt()
            create_user = True
    else:
        password_salt = bcrypt.gensalt()
        create_user = True

    session_salt = bcrypt.gensalt()
    if create_user:
        user_name = raw_input("Enter username of admin user to create: ")
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
        admin_hashedPW = bcrypt.hashpw(str(admin_pw), str(password_salt))
        if len(list(db.users.find({"USERNAME": user_name }))) > 0:
            db.users.remove({"USERNAME": user_name})
        db.users.insert(
        {
                "USERNAME" : user_name,
                "user_admin" : "true",
                "ENABLED" : "true",
                "PASSWORD" : admin_hashedPW,
                "console" : "true",
                "date_modified" : datetime.datetime.utcnow(),
                "sensor_admin" : "true",
                "responder" : "true",
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
    config['Webserver']['db']['SECRET_KEY'] = password_salt 
    config['Webserver']['db']['SESSION_KEY'] = session_salt
    config['Webserver']['web'] = {}
    config['Webserver']['web']['session_timeout'] = sessionMinutes
    config['Webserver']['events'] = {}
    config['Webserver']['events']['max_age'] = expiredDays
    config['Webserver']['events']['flow_max_age'] = expiredflowDays
 
def setup_core():
    if os.path.exists('/usr/lib/python2.7/site-packages/Minerva'):
        logger.info('Old Minerva python modules are removed')
        shutil.rmtree('/usr/lib/python2.7/site-packages/Minerva')
    shutil.copytree('Minerva','/usr/lib/python2.7/site-packages/Minerva')
    logger.info('Minerva python modules are installed')

def setup_server():
    print("Setting up the web server\n")
    logger.info("Setting up the web server")

    hostname = raw_input("Enter hostname for webserver: ")
    logger.info("Webserver hostname set to %s" % hostname)

    bindIp = raw_input("Enter IP Address to bind to: ")
    logger.info("Webserver IP set to %s" % bindIp)

    webport = raw_input("Enter Port for webserver to run on: [443] ")
    if len(webport) == 0:
        webport = 443
    logger.info("Webserver port set to %i" % int(webport))

    threads = raw_input("Enter number of threads to respond to web requests: [8] ")
    if len(threads) == 0:
        threads = 8
    logger.info("Webserver threads set to %i" % int(threads))

    web_cert = raw_input("Enter full path of webcertificate to use (Will create one if none exists) [/var/lib/minerva/webserver/server.pem] ")
    if len(web_cert) == 0:
        web_cert = '/var/lib/minerva/webserver/server.pem'
        web_key = '/var/lib/minerva/webserver/private.pem'
    else:
        web_key = raw_input("Enter full path of web server's private key: ")
    logger.info("Web server cert set to %s" % web_cert)
    logger.info("Web server private key set to %s" % web_key)

    password_tries = raw_input("Enter # of logon attempts before user is locked out: [3] ")
    if len(password_tries) == 0:
        password_tries = 3
    logger.info("Password failures set to %i" % int(password_tries))

    password_min_length = raw_input("Enter minimum length for user passwords: [8] ")
    if len(password_min_length) == 0:
        password_min_length = 8
    logger.info("Min password length is set to %i" % int(password_min_length))

    password_max_age = raw_input("Enter # of days a password is valid before needed to be changed: [90] ")
    if len(password_max_age) == 0:
        password_max_age = 90
    logger.info("Max password age set to %i" % int(password_max_age))

    pcap_timeout = raw_input("Enter # of seconds to wait on a pcap request: [300] ")
    if len(pcap_timeout) == 0:
        pcap_timeout = 300
    logger.info("Pcap request timeout set to %i" % int(pcap_timeout))

    maxResults = raw_input("Enter # of results to show in the console at a time: [5000] (15000 max) ")
    if len(maxResults) == 0:
        maxResults = 5000
    elif int(maxResults) > 15000:
        maxResults = 15000
    logger.info("Max events set to %i" % int(maxResults))

    lower_count = raw_input("Enter minimum # of lower case letters in a password: [2] ")
    if len(lower_count) == 0:
        lower_count = 2
    logger.info("Min password lower case set to %i" % int(lower_count))

    upper_count = raw_input("Enter minimum # of upper case letters in a password: [2] ")
    if len(upper_count) == 0:
        upper_count = 2
    logger.info("Min password upper case set to %i" % int(upper_count))

    digit_count = raw_input("Enter minimum # of numbers in a password: [2] ")
    if len(digit_count) == 0:
        digit_count = 2
    logger.info("Min numbers in a password set to %i" % int(digit_count))

    special_count = raw_input("Enter minimum # of special characters in a password: [2] ")
    if len(special_count) == 0:
        special_count = 2
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
    print("Setting up the event receiver\n")
    logger.info("Setting up the event receiver")
    listen_ips = {}
    while True:
        listen_ip = raw_input("Enter IP Address to listen on: ")
        logger.info("Adding listener ip %s" % listen_ip)
        listen_ips[listen_ip] = {}
        listen_ips[listen_ip]['ports'] = []
        while True:
            listen_port = raw_input("Enter port to listen on: ")
            logger.info("Adding listener port %i" % int(listen_port))
            listen_ips[listen_ip]['ports'].append(int(listen_port))
            resp = raw_input("Do you want to add more ports? [y/n] ")
            if resp == 'n' or resp == 'N':
                break
        listen_ips[listen_ip]['receive_threads'] = int(raw_input("How many threads do you want to process events? "))
        logger.info("Setting receive threads at %i" % listen_ips[listen_ip]['receive_threads'])
        resp1 = raw_input("Do you want to add another IP? [y/n] ")
        if resp == 'n' or resp == 'N':
            break
    listener_timeout = raw_input("Enter number of seconds to timeout on a single receive thread: [20] ")
    if len(listener_timeout) == 0:
        listener_timeout = 20
    logger.info("Setting listener timeout at %i seconds" % int(listener_timeout))

    ins_threads = raw_input("Enter number of processes you want to insert alerts: [4] ")
    if len(ins_threads) == 0:
        ins_threads = 4
    logger.info("Setting inserter threads to %i" % int(ins_threads))

    ins_batch = raw_input("Enter max number of events to insert at a time: [500] ")
    if len(ins_batch) == 0:
        ins_batch = 500
    logger.info("Setting max events to insert to %i" % int(ins_batch))

    ins_wait = raw_input("Enter max seconds to wait before inserting events: [20] ")
    if len(ins_wait) == 0:
        ins_wait = 20
    logger.info("Setting max seconds before inserting to %i seconds" % int(ins_wait))

    rec_cert = raw_input("Enter full path of certificate to use (will create in this lcoation if it doenst exist): [/var/lib/minerva/receiver/server.pem] ")
    if len(rec_cert) == 0:
        rec_cert = '/var/lib/minerva/receiver/server.pem'
        rec_key = '/var/lib/minerva/receiver/private.pem'
    else:
        rec_key = raw_input("Enter full path of private key to use w/ the certificate above: ")
    logger.info("Certificate path set to %s" % rec_cert)
    logger.info("Private key path set to %s" % rec_key)

    pcap_ip = raw_input("Enter IP Address to listen for pcap requests from the webserver: ")
    logger.info("PCAP listening IP set to %s" % pcap_ip)

    pcap_port = raw_input("Enter Port of Receiver to list for pcap requests for: [10009] ")
    if len(pcap_port) == 0:
        pcap_port = 10009
    logger.info("PCAP listening port set to %i" % int(pcap_port))

    pcap_threads = raw_input("Enter number of threads to process pcap requests: [4] ")
    if len(pcap_threads) == 0:
        pcap_threads = 4
    logger.info("Threads processing PCAP requests set to %i" % int(pcap_threads))

    pcap_timeout = raw_input("Enter number of seconds to wait for a pcap request, Should be the same as webserver value: [300] ")
    if len(pcap_timeout) == 0:
        pcap_timeout = 300
    logger.info("PCAP Request timeout set to %i seconds" % int(pcap_timeout))

    config['Event_Receiver'] = {}
    config['Event_Receiver']['listen_ip'] = listen_ips
    config['Event_Receiver']['listener_timeout'] = listener_timeout
    config['Event_Receiver']['insertion_threads'] = int(ins_threads)
    config['Event_Receiver']['insertion_batch'] = int(ins_batch)
    config['Event_Receiver']['insertion_wait'] = int(ins_wait)
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
    print("Setting up the agent\n")
    logger.info("Setting up the agent")

    sensor_name = raw_input("Enter name of sensor: ")
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
        lfile = raw_input("Enter full pathname of log file to send in: ")
        logger.info("Log file %s added" % lfile)

        ltype = raw_input("Enter alert type of log file: (suricata_eve_alert, suricata_eve_flow,  snort_alert, suricata_alert): ")
        logger.info("Log file type is %s" % ltype)

        pfile = raw_input("Enter full pathname of position file: ")
        logger.info("Position file is set to %s" % pfile)

        logfiles[lfile] = {}
        logfiles[lfile]['type'] = ltype
        logfiles[lfile]['position_file'] = pfile
        resp = raw_input("Do you want to add more log files? [y/n] ")
        if resp == 'n' or resp == 'N':
            break

    server_cert = raw_input("Enter full pathname of where to save server cert: [/var/lib/minerva/agent/server.pem] ")
    if len(server_cert) == 0:
        server_cert = '/var/lib/minerva/agent/server.pem'
    logger.info("Path to store server cert is set to %s" % server_cert)

    destination = raw_input("Enter IP address of receiver to send to: ")
    logger.info("Receiver destination of %s set" % destination)

    dest_port = int(raw_input("Enter destination port to send to: "))
    logger.info("Receiver port of %s set" % dest_port)

    send_batch = raw_input("Enter max # of events to send at once: [500] ")
    if len(send_batch) == 0:
        send_batch = 500
    logger.info("Max events to send at once is set to %i" % int(send_batch))

    send_wait = raw_input("Enter max # of seconds to wait to send events (Will send earlier if max events is reached): [10] ")
    if len(send_wait) == 0:
        send_wait = 10
    logger.info("Max wait time between sending events is set to %i" % int(send_wait))

    print("Configuring Agent PCAP Requests")
    logger.info("Configuring Agent PCAP Requests")

    max_packets = raw_input("Enter max # of packets to return per request: [10000] ")
    if len(max_packets) == 0:
        max_packets = 10000
    logger.info("Max packets to return per request is set to %i" % int(max_packets))

    max_size = raw_input("Enter Max size(mb) of pcap files to return per reqeust: [20] ")
    if len(max_size) == 0:
        max_size = 20
    logger.info("Max size of pcap request is set to %i mb" % int(max_size))

    max_files = raw_input("Enter Max # of pcap files to search through per request: [10] ")
    if len(max_files) == 0:
        max_files = 10
    logger.info("Max # of files to search through is set to %i" % int(max_files))

    thres_time = raw_input("Enter max time in seconds past an event to grab packets for: [300] ")
    if len(thres_time) == 0:
        thres_time = 300
    logger.info("Max time window is set to %i seconds" % int(thres_time))

    prefix = raw_input("Enter prefix for pcap files: []")
    suffix = raw_input("Enter suffix for pcap files: [.pcap] ")
    if len(suffix) == 0:
        suffix = '.pcap'
    logger.info("PCAP Prefix is set to %s" % prefix)
    logger.info("PCAP suffix is set to %s" % suffix)

    pcap_directory = raw_input("Enter complete path to base directory for pcap files: ")
    logger.info("PCAP storage directory is set to %s" % pcap_directory)

    temp_directory = raw_input("Enter complete path of temp storage for pcap requests: ")
    logger.info("PCAP temp directory is set to %s" % pcap_directory)

    if not os.path.exists(temp_directory):
        logger.info("PCAP temp dir doesn't exist, creating it")
        os.makedirs(temp_directory)

    listener_ip = raw_input("Enter ip address to listen for requests on: ")
    logger.info("PCAP Listener bound to %s" % listener_ip)

    listener_port = raw_input("Enter port to listen for requests on: [10009] ")
    if len(listener_port) == 0:
        listener_port = 10009
    logger.info("PCAP Listener port set to %i" % int(listener_port))

    listener_threads = raw_input("Enter number of threads to process requests: [4] ")
    if len(listener_threads) == 0:
        listener_threads = 4
    logger.info("PCAP Processing threads set to %i" % int(listener_threads))

    config['Agent_forwarder'] = {}
    config['Agent_forwarder']['sensor_name'] = sensor_name
    config['Agent_forwarder']['client_cert'] = client_cert
    config['Agent_forwarder']['client_private'] = client_key
    config['Agent_forwarder']['logfiles'] = logfiles
    config['Agent_forwarder']['target_addr'] = {}
    config['Agent_forwarder']['target_addr']['server_cert'] = server_cert
    config['Agent_forwarder']['target_addr']['destination'] = destination
    config['Agent_forwarder']['target_addr']['port'] = int(dest_port)
    config['Agent_forwarder']['target_addr']['send_batch'] = int(send_batch)
    config['Agent_forwarder']['target_addr']['send_wait'] = int(send_wait)
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
    tmp = env.get_template('minerva.yaml')
    conf_file = open(os.path.join(install_path,'etc/minerva.yaml'),'w')
    conf_write = tmp.render(config)
    conf_file.writelines(tmp.render({ "config": config }))
    conf_file.close()

def main():
    global config, install_path, logger
    logging.basicConfig(format='%(asctime)s: %(message)s',filename='setup.log', level=logging.DEBUG)
    logger = logging.getLogger()
    logger.info('********************************************************************************************************************************')
    logger.info('Starting Minerva Setup')
    config = {}
    while(True):
        print("Please choose an install method:\n\t1.\tStandAlone (Server, Agent and Receiver)\n\t2.\tServer/Receiver\n\t3.\tWebServer only\n\t4.\tReceiver Only\n\t5.\tAgent Only\n\t6.\tDatabase Only\n\t")
        install_type = raw_input()
        if int(install_type) >= 1 and int(install_type) < 7:
            logger.info('Choosing install option %i' % int(install_type))
            break
        else:
            print('Invalid Option')
            logger.error('Invalid option %s' % install_type)
    location = raw_input("Enter installation Directory: ")
    logger.info('Installation Directory is %s' % location)
    if os.path.exists(location):
        if os.path.exists(os.path.join(location,'/bin/')):
            logger.info('%s exists' % location)
            resp = raw_input("Previous Installation Detected, Install over it? [y/n]")
            if resp == 'y' or resp == 'Y':
                install_path = location
            logger.warning('Write installtion option chosen is %s' % resp )
        else:
            install_path = os.path.join(location,'minerva')
            logger.info('Installing in to %s' % install_path)
            os.makedirs(os.path.join(install_path,'bin'))
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
        resp = raw_input('Connect to existing database? [y/n] ')
        if resp == 'y' or resp == 'Y':
            setup_db_lite()
        else:
            setup_db()
        setup_server()
        setup_core()
        setup_receiver()
        setup_agent()
    elif int(install_type) == 2:
        check_server()
        check_receiver()
        resp = raw_input('Connect to existing database? [y/n] ')
        if resp == 'y' or resp == 'Y':
            setup_db_lite()
        else:
            setup_db()
        setup_server()
        setup_core()
        setup_receiver()
    elif int(install_type) == 3:
        check_server()
        resp = raw_input('Connect to existing database? [y/n] ')
        if resp == 'y' or resp == 'Y':
            setup_db_lite()
        else:
            setup_db()
        setup_server()
        setup_core()
    elif int(install_type) == 4:
        check_receiver()
        resp = raw_input('Connect to existing database? [y/n] ')
        if resp == 'y' or resp == 'Y':
            setup_db_lite()
        elif resp == 'n' or resp == 'N':
            setup_db()
        setup_core()
        setup_receiver()
    elif int(install_type) == 5:
        check_agent()
        setup_core()
        setup_agent()
    logger.info('Writing Config to disk')
    write_config()
    logger.info('********************************************************************************************************************************')
main()
