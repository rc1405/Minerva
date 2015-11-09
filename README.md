#Minerva

Minerva is an IDS event manager based on python and mongodb. Minerva currently supports Suricata eve logs as the primary source of data through the eve alert and flow logs and Snort Fast log formats. Functionality will be expanded to include Bro ascii and json log inputs as well as other netflow inputs.

##Components

###Web Server

The web server runs on cherrypy and has the following views:

####Console:

The console provides the initial alert triage functionality. It displays events by priority, then by date. It allows the user to highlight one to many events to escalate for additional review, close, comment and pull additional details relating to the event; associated netflow data or PCAP from the sensor.



####Escalated Events:

This menu provides the final layer of analysis on the events. The look is the same as the console and provides the same options for retreiving additional data about the alert. It also allows the user to close and comment on events.



####Search Alerts:
This menu provide a mechanism to search through all alerts within the database.  Alerts can be searched over a timeframe or on any field appearing within the console view.  From this menu, alerts can have comments added, or have the state closed or changed (Close to Escalated).



####Search Flow:
This menu provides a mechanism to search through all netflow relating data in the database.  



####Sensors:

This menu provides management type activities for sensors reporting into the Event Receiver. The sensor menu will provide a place to enable or disable sensors and will identify if information relating to the sensor changes such as the IP address or certificate.



####User Management:

This menu provides access to allow modification and creation of users. Modifications include password and permission changes; and enable/disable options. Permissions are assigned on a role basis and are associated with each of the available menus. Permissions are: console, responder, sensor_admin, user_admin and server_admin.



####Server Administration:

This menu provides configurable options such as: server hostname, server port, mongodb url, mongodb port, mongodb user, mongodb password, event expiration.

###Event Receiver

This process is responsible for validation and collection of events from the sensors and inserting them into the db.  It also provides as a proxy to request PCAP from a given sensor for the webserver.

###Sensor Agent

This process is responsible for tail and keeping track of events generated and send to the event receiver and to carve PCAP for a given alert or session requested.
