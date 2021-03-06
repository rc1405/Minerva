#Installation Guide

##Mongo DB
Download and install mongodb 3.x according to your distribution.  Additional resources found here: https://www.mongodb.org/downloads#production.

###Mongo DB Sample Configuration
Included in minerva-ids/examples.  Make sure mongodb is started before running setup.  If authentication is required, it must be setup beforehand.  The database name is minerva.  See https://docs.mongodb.org/manual/tutorial/enable-authentication/ for instructions on how to enable mongodb authentication

##Required Packages
- openssl
- yaml
- pip
- m2crypto
- libpcap

##Python Required Packages
###All
- PyYAML
- M2Crypto
- pytz
- python-datutil

###Webserver
- jinja2
- markupsafe
- pymongo
- cherrypy

###Agent
- pypcap
- dpkt*

*I ran into issues installing dpkt with pip but had no issues installing from google code https://code.google.com/p/dpkt/

###Receiver
- pymongo

###Setup with pip 
** I found it easier to install M2Crypto through packages instead of pip.  There seems to be a good amount of additional dependencies required if building through pip.
- Install all requirements: pip install -r requirements.txt
- Install webserver requirements only: pip install -r requirements/webserver_requirements.txt
- Install receiver requirements only: pip install -r requirements/receiver_requirements.txt
- Install agent requirements only: pip install -r requirements/agent_requirements.txt

##Setup
After requirements are installed and mongodb is running; cd to minerva-ids/bin and run 'python setup.py'.  Input information as prompted. 

###Installation Options are as follows:
####1.  StandAlone (Server, Agent and Receiver)
Sets up all three main components of Minerva-IDS.  Server, which is the web front end to manage, view and seach alerts and netflow.  Agent, which is the process that sends in events to be inserted into the database.  Receiver, which is the process that vets events coming in and inserts them into the database

####2.  Server/Receiver
Sets up the webserver and receiver functions

####3.  WebServer only
Sets up only the webserver front end

####4.  Receiver Only
Sets up only the receiver process

####5.  Agent Only
Sets up only the event forwarder Agent

####6. Database Only
Sets up the database only.  Creates the database, collections and indexes.  If Authentication is required, it needs to be configured prior to running the setup process.

##Running
###Webserver
cd $INSTALL_DIR/bin
python webserver.py

See examples/example_webserver.service for a sample systemd service file

###Receiver
cd $INSTALL_DIR/bin

python receiver.py

See examples/example_receiver.service for a sample systemd service file

###Agent
cd $INSTALL_DIR/bin

python agent.py

See examples/example_agent.service for a sample systemd service file

###How To Access
Now that Minerva-IDS is up in running, open up your web browser and navigate to https://$SERVER_IP:$SERVER_PORT  where $SERVER_IP and $SERVER_PORT are the webserver inputs specified during setup.  Chrome and Firefox have been tested, all others are not supported.

##MongoDB Cluster Setup
###Required Shard Keys if using a MongoDB Sharded Setup
####alerts
{ _id: "hashed" }
####flow
{ _id: "hashed" }
####dns
{ _id: "hashed" }
####certs
{ "SERVER": "hashed" }
####keys
{ "SERVER": "hashed" }
####filters
{ _id: "hashed" }
####users
{ "USERNAME": "hashed" }
####sessions
{ "session_id": "hashed" }
####watchlist
 { "type": "hashed" }
####signatures
{ "sig_id": 1, "gen_id": 1, "rev": 1 }
