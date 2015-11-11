#Minerva

Minerva is an IDS event manager based on python and mongodb. Minerva currently supports Suricata EVE logs and Snort Fast log formats as the primary source of data for alert and flow logs. Functionality will be expanded in the future to include Bro ascii and json log inputs, and other netflow sources, in the future.

##Components

###Web Server

The web server runs on cherrypy and has the following views:

###Console:

The console provides the initial alert triage functionality. It displays events by priority, then by date. It allows the user to highlight one to many events to escalate for additional review, close, comment, investigate additional details relating to the event. The additional details includes the original alert, the ascii packet (if available through Suricata's eve log) and any session data within relating to the time frame.

![alt tag](http://imgur.com/XeJ7ici)

###Escalated Events:

This menu provides the final layer of analysis on the events. The look is the same as the console and provides the same options for retreiving additional data about the alert. It also allows the user to close and comment on events.



 

###Investigate:

Additional information may be pivoted from the event consoles.  Such information includes the original event, ASCII payload if available, previous comments and any netflow associated with the session.  From this menu, the analyst has the same options as the console pages; they can comment, close, escalate or request PCAP for a given event.



###Search Flow:

This menu provides a mechanism to search netflow records of any source and request PCAP for desired sessions.



###Search Alerts:

This menu provides a mechanism to search through alerts and change and/or perform additional research.  This is where a accidentally closed event can be re-opened for example.



###Sensors:

This menu provides management type activities for sensors reporting into the Event Receiver. Status options are APPROVED, NOT_APPROVED, CERT_CHANGED, and DENIED. APPROVED is what allows the event receiver to insert events from the given sensor. The remaining three states prevent events from being loaded. NOT_APPROVED is a sensor that has just checked in and waiting for approval to accept events. CERT_CHANGED indicates that a server name and IP are the same but the authenticating certificate differs that that of what was accepted.



 

###User Management:

This menu provides access to allow modification and creation of users. Modifications include password and permission changes; and enable/disable options. Permissions are assigned on a role basis and are associated with each of the available menus. Permissions are: console, responder, sensor_admin, user_admin and server_admin.



###Server Administration:

This menu provides configurable options such as: server hostname, server port, mongodb url, mongodb port, mongodb user, mongodb password, event expiration.



##Event Receiver

This process is responsible for validation and collection of events from the sensors and inserting them into the db.

##Sensor Agent

This process is responsible for tail and keeping track of events generated and send to the event receiver.
