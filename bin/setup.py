import pymongo
import os
import sys
import copy

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
def format_db()
    if 'minerva' in client.database_names():
        client.drop_database('minerva')
    database = client.minerva
    database.create_collection('alerts')
    database.create_collection('flow')
    database.create_collection('users')
    database.create_collection('sensors')
    database.create_collection('sessions')
    alerts = database.alerts
    alerts.create_index([("MINERVA_STATUS", pymongo.ASCENDING),("alert.severity", pymongo.DESCENDING),("epoch", pymongo.ASCENDING)])
    alerts.create_index([("epoch", pymongo.ASCENDING),( "expireAfterSeconds", alert_threshold )])
    flow = database.flow
    flow.create_index([("src_ip", pymongo.ASCENDING),("src_port", pymongo.ASCENDING),("dest_ip", pymongo.ASCENDING),( "dest_port", pymongo.ASCENDING),("proto": pymongo.ASCENDING))
    flow.create_index([("timestamp", pymongo.ASCENDING), ( "expireAfterSeconds", 86400)])
    users = database.users
    users.insert({'adminuser'})
    

def setup_db()
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
        password = raw_input("Enter a password: ")
    else:
        username = 'NA'
        password = 'NA'
    client = pymongo.MongoClient(ip,int(port))
    db = client.minerva
    if 'minerva' in client.database_names():
        resp = raw_input('Database already exists, do you want to keep it?i [N]')
        if resp == 'Y' or resp == 'y':
            keep_db = True
        else:
            keep_db = False
            db.drop_database('minerva')
    try:
        tmp =  len(db.list_collections())
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
    db.alerts.create_index({"MINERVA_STATUS": 1, "alert.severity": -1, "timestamp": 1 })
    expiredDays = raw_input("Enter number of days to keep alerts: ")
    expiredSeconds = int(expiredDays) * 86400
    db.alerts.create_index({"timestamp": 1, "$expireAfterSeconds": expiredSeconds })
    db.flow.create_index({"src_ip": 1, "src_port": 1, "dest_ip": 1, "dest_port": 1, "proto": 1 })
    expiredflowDays = raw_input("Enter number of days to keep flow data: ")
    flowexpiredSeconds = int(expiredflowDays) * 86400
    db.flow.create_index({"timestamp": 1, "$expireAfterSeconds": flowexpiredSeconds })
    sessionMinutes = raw_input("Enter number of minutes until each console session times out: ")
    sessionTimeout = int(sessionMinutes) * 60
    db.session.create_index({ "last_accessed": 1, "$expireAfterSeconds": sessionTimeout })
    admin_pw = raw_input("Enter password for admin console user: ")
    password_salt = bcrypt.gensalt()
    session_salt = bcrypt.gensalt()
    admin_hashedPW = bcrypt.hashpw(password, password_salt)
    db.users.insert(
    {
            "USERNAME" : "admin",
            "user_admin" : "true",
            "ENABLED" : "true",
            "PASSWORD" : admin_hashedPW,
            "console" : "true",
            "date_modified" : datetime.datetime.fromtimestamp(time.time()),
            "sensor_admin" : "true",
            "responder" : "true",
            "server_admin" : "true",
            "date_created" : datetime.datetime.fromtimestamp(time.time()),
    })
    out_config['Webserver'] = {}
    out_config['Webserver']['db'] = {}
    out_config['Webserver']['db']['url'] = ip
    out_config['Webserver']['db']['port'] = port
    out_config['Webserver']['db']['useAuth'] = useAuth
    out_config['Webserver']['db']['username'] = username
    out_config['Webserver']['db']['password'] = password
    out_config['Webserver']['db']['SECRET_KEY'] = password_salt 
    out_config['Webserver']['db']['SESSION_KEY'] = session_salt
    out_config['Webserver']['web'] = {}
    out_config['Webserver']['web']['session_timeout'] = sessionMinutes
    out_config['Webserver']['events'] = {}
    out_config['Webserver']['events']['max_age'] = expiredDays
    out_config['Webserver']['events']['flow_max_index_age'] = expiredflowDays
 
def setup_core():
    shutil.copy('Minerva','/usr/lib/python2.7/site-packages/')
def setup_server():
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
    setup webserver stuff, sysinit, systemctl type stuff
    out_config['Webserver']['web']['hostname'] = hostname
    out_config['Webserver']['web']['bindIp'] = bindIp
    out_config['Webserver']['web']['port'] = webport
    out_config['Webserver']['web']['threads'] = threads
    out_config['Webserver']['web']['certs'] = {}
    out_config['Webserver']['web']['webserver_cert'] = web_cert
    out_config['Webserver']['web']['webserver_key'] = web_key
    out_config['Webserver']['web']['password_tries'] = password_tries
    out_config['Webserver']['web']['password_min_length'] = password_min_length
    out_config['Webserver']['web']['password_max_age'] = password_max_age
    out_config['Webserver']['events']['maxResults'] = maxResults
    os.makedirs(os.path.join(location,'bin/templates'))
    os.makedirs(os.path.join(location,'bin/static'))
    shutil.copy('templates',os.path.join(location,'bin/templates'))
    shutil.copy('static',os.path.join(location,'bin/static'))
    shutil.copy('webserver.py',os.path.join(location,'bin/webserver.py'))
def setup_receiver():
    listen_ips = {}
    while True:
        listen_ip = raw_input("Enter IP Address to listen on: ")
        listen_ips[listen_ip] = []
        while True:
            listen_port = raw_input("Enter port to listen on: ")
            listen_ips[listen_ip].append(int(listen_port))
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
    out_config['Event_Receiver'] = {}
    out_config['Event_Receiver']['listen_ip'] = listen_ips
    out_config['Event_Receiver']['certs'] = {}
    out_config['Event_Receiver']['certs']['server_cert'] = rec_cert
    out_config['Event_Receiver']['certs']['private_key'] = rec_key
    shutil.copy('receiver.py',os.path.join(location,'bin'))
def setup_agent():
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
    if len(server_cert) = 0:
        server_cert = '/var/lib/minerva/agent/server.pem'
    destination = raw_input("Enter IP address of receiver to send to: ")
    dest_port = int(raw_input("Enter destination port to send to: "))
    send_batch = raw_input("Enter max # of events to send at once: [500] ")
    if len(send_batch) == 0:
        send_batch = 500
    send_wait = raw_input("Enter max # of seconds to wait to send events (Will send earlier if max events is reached): [10] ")
    if len(send_wait) == 0:
        send_wait = 10
    out_config['Agent_forwarder'] = {}
    out_config['Agent_forwarder']['sensor_name'] = sensor_name
    out_config['Agent_forwarder']['client_cert'] = client_cert
    out_config['Agent_forwarder']['client_private'] = client_key
    out_config['Agent_forwarder']['logfiles'] = logfiles
    out_config['Agent_forwarder']['target_addr'] = {}
    out_config['Agent_forwarder']['target_addr']['server_cert'] = server_cert
    out_config['Agent_forwarder']['target_addr']['destination'] = destination
    out_config['Agent_forwarder']['target_addr']['port'] = int(dest_port)
    out_config['Agent_forwarder']['target_addr']['send_batch'] = int(send_batch)
    out_config['Agent_forwarder']['target_addr']['send_wait'] = int(send_wait)
    shutil.copy('agent.py',os.path.join(location,'bin'))

def write_config():
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader('templates'))
            tmp = env.get_template('users.html')
            return tmp.render(context_dict


def main():
    out_config = {}
    while(True):
        print("Please choose an install method:\n\t1.\tStandAlone (Server, Agent and Receiver)\n\t2.\tServer/Receiver\n\t3.\tWebServer only\n\t4.\tReceiver Only\n\t5.\tAgent Only\n\t")
        intall_type = raw_input()
        if int(intall_type) > 1 and int(intall_type) < 6:
            break
        else:
            print('Invalid Option')
    location = raw_input("Enter installation Directory: ")
    if os.path.exists(location):
        install_path = os.path.join(location,'minerva')
    else:
        try:
            os.makedirs(location)
            os.makedirs(os.path.join(location,'bin'))
            os.makedirs(os.path.join(location,'etc'))
            install_path = location
        except:
            print("Unable to make directory %s, check permissions and try again" % location)
            sys.exit()
    if intall_type == 1:
        check_server()
        check_agent()
        check_receiver()
        setup_db()
        setup_server()
        setup_core()
        setup_receiver()
        setup_agent()
    elif intall_type == 2:
        check_server()
        check_receiver()
        setup_db()
        setup_server()
        setup_core()
        setup_receiver()
    elif intall_type == 3:
        check_server()
        setup_db()
        setup_server()
        setup_core()
    elif intall_type == 4:
        check_receiver()
        setup_db()
        setup_core()
        setup_receiver()
    elif intall_type == 5:
        check_agent()
        setup_core()
        setup_agent()
main()
