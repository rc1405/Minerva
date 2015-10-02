import pymongo
import os
import sys

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
    ip = raw_input('Please enter database ip: [127.0.0.1] ')
    if len(ip) == 0:
        ip = '127.0.0.1'
    port = raw_input('Please enter database port: [27017] ')
    if len(port) == 0:
        port = 27017
    useAuth = raw_input('Use db authentication? Y/N [N] ')
def setup_core():
def setup_server():
def setup_receiver():
def setup_agent():
def main():
    check_server()
    check_agent()
    check_receiver()
    while(True):
        print("Please choose an install method:\n\t1.\tStandAlone (Server, Agent and Receiver)\n\t2.\tServer/Receiver\n\t3.\tWebServer only\n\t4.\tReceiver Only\n\t5.\tAgent Only")
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
            install_path = location
        except:
            print("Unable to make directory %s, check permissions and try again" % location)
            sys.exit()
    if intall_type == 1:
        setup_core()
        setup_db()
        setup_server()
        setup_receiver()
        setup_agent()
    elif intall_type == 2:
        setup_core()
        setup_db()
        setup_server()
        setup_receiver()
    elif intall_type == 3:
        setup_core()
        setup_db()
        setup_server()
    elif intall_type == 4:
        setup_core()
        setup_db()
        setup_receiver()
    elif intall_type == 5:
        setup_core()
        setup_agent()
main()
