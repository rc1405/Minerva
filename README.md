# Release Notes:

## Version 2:
* Complete overhaul of receiver and transport.  
    * Eliminated raw sockets and moved to utilizing ZeroMQ
    * Clean up of unneeded transformations and additions
* Redesign of Agent forwarder and log ingestion
    * Better log collection performance
    * Faster resumption after stoppage
* Overhaul of encryption
    * x509 Certificates still used for authentication and key exchange
    * Event transport now utilizes AES keys, updated on an hourly basis
* New Watchlist Capability
    * Upload single entries or text files with IP or domain indicators
    * Alerts will be generated off of traffic seen and available in the console
* Added HEX view to investigate pannel
* Collections Added
    * certs
        * Storage of certs and approval for webservers, receivers and sensors
    * keys
        * Storage of cycling AES keys
* Collections Removed
    * sensors
        * Data moved to certs collection
* Dependencies Added
    * Yara
    * yara-python
    * ZeroMQ
    * pyzmq
* Dependencies Removed
    * numpy
    * redis - Removed from receiver.  Only needed on Agent for Suricata EVE logs in Redis

#Minerva

Minerva is an IDS event manager based on python and mongodb. Minerva currently supports Suricata EVE logs and Snort Fast log formats as the primary source of data for alert and flow logs. Functionality will be expanded to include Bro ascii and json log inputs, and other netflow sources in the future.

##Components

###Web Server

The web server runs on cherrypy and has the following views:

###Console:

The console provides the initial alert triage functionality. It displays events by priority, then by date. It allows the user to highlight one to many events to escalate for additional review, close, comment, investigate additional details relating to the event. The additional details includes the original alert, the ascii packet (if available through Suricata's eve log) and any session data within relating to the time frame.



###Escalated Events:

This menu provides the final layer of analysis on the events. The look is the same as the console and provides the same options for retreiving additional data about the alert. It also allows the user to close and comment on events.



###Investigate:

Additional information may be pivoted from the event consoles.  Such information includes the original event, ASCII payload if available, previous comments and any netflow associated with the session.  From this menu, the analyst has the same options as the console pages; they can comment, close, escalate or request PCAP for a given event.



###Event Watchlist:
This feature allows responders to perform static indicator matching against known malicious indicators.  Users can input single entries or submit line delimited text files to be added to the watchlist.  Accepted entries are single IP Addresses, CIDR ranges and Domain name matches.


###Event Filters:
This menu provides the ability to implement a mass categorization of alerts.  Categorizations can be accomplished by the signature ID, individual IP Address, IP address pairs, or by an signature classification.  Changes can be a change in state from Open to escalated or closed.  It can also increase or decrease the priority of a alerts that meet a given criteria.

Mass categorizations can be a one time event to classify all alerts that meet a given criteria, or submitted to be a temporary filter for incoming events.  Temporary filters can be then made permanent should you decide to keep them.  The expiration for temporary filters is 24 hours by default and can be increased or decreased at any time through the config page.


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
