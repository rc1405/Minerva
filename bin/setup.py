import pymongo
import os
import sys
import copy
import datetime
import time
import shutil
import getpass

def check_server():
    try:
        import pymongo
    except:
        print('Pymongo not installed')
        sys.exit()
    try:
        import M2Crypto
    except:
        print('M2Crypto not installed')
        sys.exit()
    try:
        import cherrypy
    except:
        print('Cherrypy not installed')
        sys.exit()
    try:
        import jinja2
    except:
        print('Jinja2 not installed')
        sys.exit()
    try:
        import yaml
    except:
        print('PyYAmL not installed')
        sys.exit()
    try:
        import dateutil
    except:
        print('python-dateutil not installed')
        sys.exit()
    try:
        import pytz
    except:
        print('pytz not installed')
        sys.exit()
    try:
        import bcrypt
    except:
        print('bcrypt is not installed')
        sys.exit()
def check_agent():
    try:
        import M2Crypto
    except:
        print('M2Crypto not installed')
        sys.exit()
    try:
        import yaml
    except:
        print('PyYAmL not installed')
        sys.exit()
def check_receiver():
    try:
        import yaml
    except:
        print('PyYAmL not installed')
        sys.exit()
    try:
        import M2Crypto
    except:
        print('M2Crypto not installed')
        sys.exit()
    try:
        import pymongo
    except:
        print('Pymongo not installed')
        sys.exit()
    try:
        import pytz
    except:
        print('pytz not installed')

def setup_db():
    print("Setting up the Database\n")
    import pymongo
    import bcrypt
    ip = raw_input('Please enter database ip: [127.0.0.1] ')
    if len(ip) == 0:
        ip = '127.0.0.1'
    port = raw_input('Please enter database port: [27017] ')
    if len(port) == 0:
        port = 27017
    useAuth = raw_input('Use db authentication? Y/N [N] ')
    if useAuth == 'y' or useAuth == 'Y':
        username = raw_input("Enter a username: ")
        print('Enter a password: ')
        password = getpass.getpass()
    else:
        username = 'NA'
        password = 'NA'
    client = pymongo.MongoClient(ip,int(port))
    db = client.minerva
    if 'minerva' in client.database_names():
        resp = raw_input('Database already exists, do you want to keep it? [N]')
        if resp == 'Y' or resp == 'y':
            keep_db = True
        else:
            keep_db = False
            client.drop_database('minerva')
    try:
        tmp =  len(db.collection_names())
    except:
        try:
            db.authenticate(username, password)
        except:
            print('Unable to connect to database')
            sys.exit()
    db.create_collection('alerts')
    db.create_collection('flow')
    db.create_collection('sessions')
    db.create_collection('users')
    db.alerts.create_index([("MINERVA_STATUS", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("epoch", pymongo.ASCENDING)])
    expiredDays = raw_input("Enter number of days to keep alerts: ")
    expiredSeconds = int(expiredDays) * 86400
    #db.alerts.create_index([("timestamp", pymongo.ASCENDING),("expireAfterSeconds", expiredSeconds)])
    db.alerts.ensure_index("timestamp",expireAfterSeconds=expiredSeconds)
    db.flow.create_index([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),("dest_port", pymongo.ASCENDING),("proto", pymongo.ASCENDING)])
    expiredflowDays = raw_input("Enter number of days to keep flow data: ")
    flowexpiredSeconds = int(expiredflowDays) * 86400
    #db.flow.create_index([("timestamp", pymongo.ASCENDING),("expireAfterSeconds", flowexpiredSeconds)])
    db.flow.ensure_index("timestamp",expireAfterSeconds=flowexpiredSeconds)
    sessionMinutes = raw_input("Enter number of minutes until each console session times out: ")
    sessionTimeout = int(sessionMinutes) * 60
    #db.sessions.create_index([("last_accessed", pymongo.ASCENDING),("expireAfterSeconds", sessionTimeout)])
    db.sessions.ensure_index("last_accessed",expireAfterSeconds=sessionTimeout)
    #admin_pw = raw_input("Enter password for admin console user: ")
    while True:
        print('Enter admin password: ')
        admin_pw = getpass.getpass()
        print('Re-enter admin password: ')
        admin_pw2 = getpass.getpass()
        if admin_pw == admin_pw2:
            break
        else:
            print("Passwords do not match")
    password_salt = bcrypt.gensalt()
    session_salt = bcrypt.gensalt()
    admin_hashedPW = bcrypt.hashpw(str(admin_pw), str(password_salt))
    db.users.insert(
    {
            "USERNAME" : "admin",
            "user_admin" : "true",
            "ENABLED" : "true",
            "PASSWORD" : admin_hashedPW,
            "console" : "true",
            "date_modified" : datetime.datetime.utcnow(),
            "sensor_admin" : "true",
            "responder" : "true",
            "server_admin" : "true",
            "date_created" : datetime.datetime.utcnow(),
    })
    config['Webserver'] = {}
    config['Webserver']['db'] = {}
    config['Webserver']['db']['url'] = ip
    config['Webserver']['db']['port'] = port
    config['Webserver']['db']['useAuth'] = useAuth
    config['Webserver']['db']['username'] = username
    config['Webserver']['db']['password'] = password
    config['Webserver']['db']['SECRET_KEY'] = password_salt 
    config['Webserver']['db']['SESSION_KEY'] = session_salt
    config['Webserver']['web'] = {}
    config['Webserver']['web']['session_timeout'] = sessionMinutes
    config['Webserver']['events'] = {}
    config['Webserver']['events']['max_age'] = expiredDays
    config['Webserver']['events']['flow_max_index_age'] = expiredflowDays
 
def setup_core():
    if os.path.exists('/usr/lib/python2.7/site-packages/Minerva'):
        shutil.rmtree('/usr/lib/python2.7/site-packages/Minerva')
    shutil.copytree('Minerva','/usr/lib/python2.7/site-packages/Minerva')
def setup_server():
    print("Setting up the web server\n")
    hostname = raw_input("Enter hostname for webserver: ")
    bindIp = raw_input("Enter IP Address to bind to: ")
    webport = raw_input("Enter Port for webserver to run on: [443] ")
    if len(webport) == 0:
        webport = 443
    threads = raw_input("Enter number of threads to respond to web requests: [8] ")
    if len(threads) == 0:
        threads = 8
    web_cert = raw_input("Enter full path of webcertificate to use (Will create one if none exists) [/var/lib/minerva/webserver/server.pem] ")
    if len(web_cert) == 0:
        web_cert = '/var/lib/minerva/webserver/server.pem'
        web_key = '/var/lib/minerva/webserver/private.pem'
    else:
        web_key = raw_input("Enter full path of web server's private key: ")
    password_tries = raw_input("Enter # of logon attempts before user is locked out: [3] ")
    if len(password_tries) == 0:
        password_tries = 3
    password_min_length = raw_input("Enter minimum length for user passwords: [8] ")
    if len(password_min_length) == 0:
        password_min_length = 8
    password_max_age = raw_input("Enter # of days a password is valid before needed to be changed: [90] ")
    if len(password_max_age) == 0:
        password_max_age = 90
    maxResults = raw_input("Enter # of results to show in the console at a time: [5000] (15000 max) ")
    if len(maxResults) == 0:
        maxResults = 5000
    elif int(maxResults) > 15000:
        maxResults = 15000
    config['Webserver']['web']['hostname'] = hostname
    config['Webserver']['web']['bindIp'] = bindIp
    config['Webserver']['web']['port'] = webport
    config['Webserver']['web']['threads'] = threads
    config['Webserver']['web']['certs'] = {}
    config['Webserver']['web']['certs']['webserver_cert'] = web_cert
    config['Webserver']['web']['certs']['webserver_key'] = web_key
    config['Webserver']['web']['password_tries'] = password_tries
    config['Webserver']['web']['password_min_length'] = password_min_length
    config['Webserver']['web']['password_max_age'] = password_max_age
    config['Webserver']['events']['maxResults'] = maxResults
    #os.makedirs(os.path.join(install_path,'bin/templates'))
    #os.makedirs(os.path.join(install_path,'bin/static'))
    shutil.copytree('templates',os.path.join(install_path,'bin/templates'))
    shutil.copytree('static',os.path.join(install_path,'bin/static'))
    shutil.copy('webserver.py',os.path.join(install_path,'bin/webserver.py'))
def setup_receiver():
    print("Setting up the event receiver\n")
    listen_ips = {}
    while True:
        listen_ip = raw_input("Enter IP Address to listen on: ")
        listen_ips[listen_ip] = {}
        listen_ips[listen_ip]['ports'] = []
        while True:
            listen_port = raw_input("Enter port to listen on: ")
            listen_ips[listen_ip]['ports'].append(int(listen_port))
            resp = raw_input("Do you want to add more ports? [y/n] ")
            if resp == 'n' or resp == 'N':
                break
        listen_ips[listen_ip]['receive_threads'] = int(raw_input("How many threads do you want to process events? "))
        resp1 = raw_input("Do you want to add another IP? [y/n] ")
        if resp == 'n' or resp == 'N':
            break
    rec_cert = raw_input("Enter full path of certificate to use (will create in this lcoation if it doenst exist): [/var/lib/minerva/receiver/server.pem] ")
    if len(rec_cert) == 0:
        rec_cert = '/var/lib/minerva/receiver/server.pem'
        rec_key = '/var/lib/minerva/receiver/private.pem'
    else:
        rec_key = raw_input("Enter full path of private key to use w/ the certificate above: ")
    config['Event_Receiver'] = {}
    config['Event_Receiver']['listen_ip'] = listen_ips
    config['Event_Receiver']['certs'] = {}
    config['Event_Receiver']['certs']['server_cert'] = rec_cert
    config['Event_Receiver']['certs']['private_key'] = rec_key
    shutil.copy('receiver.py',os.path.join(install_path,'bin'))
def setup_agent():
    print("Setting up the agent\n")
    sensor_name = raw_input("Enter name of sensor: ")
    client_cert = raw_input("Enter full pathname of sensor certificate (One will be created if it doesn't exist): [/var/lib/minerva/agent/agent.pem] ")
    if len(client_cert) == 0:
        client_cert = '/var/lib/minerva/agent/agent.pem'
        client_key = '/var/lib/minerva/agent/private.pem'
    else:
        client_key = raw_input("Enter full pathname of sensor private key for the certificate above: ")
    logfiles = {}
    while True:
        lfile = raw_input("Enter full pathname of log file to send in: ")
        ltype = raw_input("Enter alert type of log file: (suricata_alert, suricata_flow,  snort_alert, suricata_alert, bro_conn, bro_notice): ")
        pfile = raw_input("Enter full pathname of position file: ")
        logfiles[lfile] = {}
        logfiles[lfile]['type'] = ltype
        logfiles[lfile]['position_file'] = pfile
        resp = raw_input("Do you want to add more log files? [y/n] ")
        if resp == 'n' or resp == 'N':
            break
    server_cert = raw_input("Enter full pathname of where to save server cert: [/var/lib/minerva/agent/server.pem] ")
    if len(server_cert) == 0:
        server_cert = '/var/lib/minerva/agent/server.pem'
    destination = raw_input("Enter IP address of receiver to send to: ")
    dest_port = int(raw_input("Enter destination port to send to: "))
    send_batch = raw_input("Enter max # of events to send at once: [500] ")
    if len(send_batch) == 0:
        send_batch = 500
    send_wait = raw_input("Enter max # of seconds to wait to send events (Will send earlier if max events is reached): [10] ")
    if len(send_wait) == 0:
        send_wait = 10
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
    global config, install_path
    config = {}
    while(True):
        print("Please choose an install method:\n\t1.\tStandAlone (Server, Agent and Receiver)\n\t2.\tServer/Receiver\n\t3.\tWebServer only\n\t4.\tReceiver Only\n\t5.\tAgent Only\n\t")
        intall_type = raw_input()
        if int(intall_type) >= 1 and int(intall_type) < 6:
            break
        else:
            print('Invalid Option')
    location = raw_input("Enter installation Directory: ")
    if os.path.exists(location):
        install_path = os.path.join(location,'minerva')
        os.makedirs(os.path.join(install_path,'bin'))
        os.makedirs(os.path.join(install_path,'etc'))
    else:
        try:
            os.makedirs(location)
            os.makedirs(os.path.join(location,'bin'))
            os.makedirs(os.path.join(location,'etc'))
            install_path = location
        except:
            print("Unable to make directory %s, check permissions and try again" % location)
            sys.exit()
    if int(intall_type) == 1:
        check_server()
        check_agent()
        check_receiver()
        setup_db()
        setup_server()
        setup_core()
        setup_receiver()
        setup_agent()
    elif int(intall_type) == 2:
        check_server()
        check_receiver()
        setup_db()
        setup_server()
        setup_core()
        setup_receiver()
    elif int(intall_type) == 3:
        check_server()
        setup_db()
        setup_server()
        setup_core()
    elif int(intall_type) == 4:
        check_receiver()
        setup_db()
        setup_core()
        setup_receiver()
    elif int(intall_type) == 5:
        check_agent()
        setup_core()
        setup_agent()
    write_config()
main()
