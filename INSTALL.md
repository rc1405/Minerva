#Installation Guide

##Mongo DB
Download and install mongodb 3.x according to your distribution.  Additional resources found here: https://www.mongodb.org/downloads#production

###Mongo DB Sample Configuration

systemLog:
    destination: file
    path: "/var/log/mongodb/mongod.log"
    logAppend: true

processManagement:
    fork: true
    pidFilePath: "/var/run/mongod.pid"

net:
    port: 27017
    bindIp: 127.0.0.1

storage:
    dbPath: /var/lib/mongo
    journal:
        enabled: true
    engine: wiredTiger

##Required Packages
- openssl
- yaml
- pip

##Python Required Packages
pip install -r requirements.txt

##Setup
After requirements are installed and mongodb is running; cd to minerva-ids/bin and run 'python setup.py'.  Input information as prompted.  When finished run bin/webserver.py to start web console.
